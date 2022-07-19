#!/usr/bin/env python3

import os
import sys

os.chdir(os.path.join(sys.argv[1]))

class ConfigGenerator(object):

  def __init__(self):
    self.properties = []

  def RegisterProperty(self, profileKeys, valType, default=None, transportType=None):
    self.properties.append(ConfigProperty(profileKeys, valType, default=default, transportType=transportType))

  def RegisterReadwriteProperty(self, profileKeys, valType, default=None, transportType=None):
    self.properties.append(ConfigProperty(profileKeys, valType, default=default, readWrite=True, transportType=transportType))

  def RegisterPropertyCustom(self, profileKeys, valType, getter, setter=None, transportType=None):
    self.properties.append(ConfigProperty(profileKeys, valType, getter=getter, setter=setter, transportType=transportType))

  def Generate(self):
    fh = open('SNTConfigurator.gen.h', 'w')
    fi = open('SNTConfigurator.gen.m', 'w')

    serverKeys = []
    profileKeys = []

    fh.write('#import <Foundation/Foundation.h>\n')
    fh.write('#import "Source/common/SNTConfigurator.h"\n')
    fh.write('#import "Source/common/SNTSystemInfo.h"\n\n')
    fh.write('@interface SNTConfigurator (Generated)\n\n')

    fi.write('#import "Source/common/SNTConfigurator.h"\n\n')
    fi.write('@implementation SNTConfigurator (Generated)\n\n')

    for p in self.properties:
      p._generateHeader(fh)
      p._generateImplementation(fi)
      serverKeys.extend(p._generateSyncKeyRegistration())
      profileKeys.extend(p._generateConfigKeyRegistration())

    fi.write('- (NSDictionary *)syncServerKeyTypes {\n')
    fi.write('  return @{\n')
    for key in serverKeys:
      if key:
        fi.write('    ' + key + ',\n')
    fi.write('  };\n')
    fi.write('}\n')


    fi.write('- (NSDictionary *)forcedConfigKeyTypes {\n')
    fi.write('  return @{\n')
    for key in profileKeys:
      if key:
        fi.write('    ' + key + ',\n')
    fi.write('  };\n')
    fi.write('}\n')

    fh.write('@end\n')
    fi.write('@end\n')

    fh.close()
    fi.close()


class ConfigProperty(object):

  def __init__(self, profileKeys, valType,
               default=None, readWrite=None,
               getter=None, setter=None,
               transportType=None):
    if isinstance(profileKeys, list):
      self.profileKeys = profileKeys
    else:
      self.profileKeys = [profileKeys]

    self.name = self.profileKeys[0][0].lower() + self.profileKeys[0][1:]
    self.valType = valType
    self.default = default
    self.readWrite = readWrite or (setter is not None)
    self.getter = getter
    self.setter = setter
    self.transportType = transportType

  def _generateHeader(self, f):
    f.write('@property(')
    if self.readWrite or self.setter:
      f.write('readwrite')
    else:
      f.write('readonly')
    f.write(') %s' % self.valType)
    if self.valType[-1] != '*':
      f.write(' ')
    f.write('%s;\n' % self.name)

  def _generateImplementation(self, f):
    self._generateKVO(f)
    self._generateGetter(f)
    if self.readWrite:
      self._generateSetter(f)

  def _generateKVO(self, f):
    f.write('+ (NSSet *)keyPathsForValuesAffecting%s {\n' % self.profileKeys[0])
    if self.readWrite:
      f.write('  return [self syncAndConfigStateSet];\n')
    elif self.profileKeys:
      f.write('  return [self configStateSet];\n')
    f.write('}\n\n')

  def _generateGetter(self, f):
    f.write('- (%s)%s {\n' % (self.valType, self.name))

    if self.getter:
      f.write('\n%s\n' % self.getter)
      f.write('}\n')
      return

    transportType, meth, _ = self._keyRegTypes()
    if self.readWrite:
      f.write('  %s *valOne;\n' % transportType)
      for key in self.profileKeys:
        f.write('  valOne = self.syncState[@"%s"];\n' % key)
        if meth:
          f.write('  if (valOne) return %s;\n' % (meth.replace('%v', 'valOne')))
        else:
          f.write('  if (valOne) return valOne;\n')

    f.write('  %s *valTwo;\n' % transportType)
    for key in self.profileKeys:
      f.write('  valTwo = self.configState[@"%s"];\n' % key)
      if meth:
        f.write('  if (valTwo) return %s;\n' % (meth.replace('%v', 'valTwo')))
      else:
        f.write('  if (valTwo) return valTwo;\n')

    if self.default:
      if isinstance(self.default, str):
        f.write('  return @"%s";\n' % self.default)
      elif isinstance(self.default, int):
        f.write('  return %d;\n' % self.default)
      elif isinstance(self.default, float):
        f.write('  return %f;\n' % self.default)
      elif isinstance(self.default, bool):
        if self.default:
          f.write('  return YES;\n')
        else:
          f.write('  return NO;\n')
      else:
        f.write('  return %s' % self.default)
    else:
      f.write('  return (%s)0;\n' % self.valType)
    f.write('}\n\n')

  def _generateSetter(self, f):
    f.write('- (void)set%s:(%s)v {\n' % (self.profileKeys[0], self.valType))
    if self.setter:
      f.write('\n%s\n' % self.setter)
      f.write('}\n')
      return

    transportType, _, meth = self._keyRegTypes()
    if meth:
      f.write('  [self updateSyncStateForKey:@"%s" value:%s];\n' % (self.profileKeys[0], meth.replace('%v', 'v')))
    else:
      f.write('  [self updateSyncStateForKey:@"%s" value:v];\n' % self.profileKeys[0])
    f.write('}\n\n')

  # Returns the transport type for this type, along with the encode and decode methods to use.
  # For the encode/decode methods, the value will be passed as %v.
  def _keyRegTypes(self):
    if self.transportType:
      return self.transportType, None, None
    elif self.valType.find('NSRegularExpression') == 0:
      return 'NSRegularExpression', None, None
    elif self.valType.find('NSString') == 0:
      return 'NSString', None, None
    elif self.valType.find('NSURL') == 0:
      return 'NSString', '[NSURL URLWithString:%v]', '[%v absoluteString]'
    elif self.valType.find('NSDate') == 0:
      return 'NSDate', None, None
    elif self.valType.find('NSData') == 0:
      return 'NSData', None, None
    elif self.valType.find('NSArray') == 0:
      return 'NSArray', None, None
    elif self.valType.find('NSDictionary') == 0:
      return 'NSDictionary', None, None
    elif self.valType.find('BOOL') == 0:
      return 'NSNumber', '[%v boolValue]', '@(%v)'
    elif self.valType.find('int') == 0:
      return 'NSNumber', '[%v intValue]', '@(%v)'
    elif self.valType.find('float') == 0:
      return 'NSNumber', '[%v floatValue]', '@(%v)'
    elif self.valType.find('NSUInteger') == 0:
      return 'NSNumber', '[%v unsignedIntegerValue]', '@(%v)'
    else:
      return None, None, None

  def _generateSyncKeyRegistration(self):
    if not self.readWrite:
      return []
    transportType, _, _ = self._keyRegTypes()
    if not transportType:
      return []
    keys = []
    for key in self.profileKeys:
      keys.append('@"%s" : [%s class]' % (key, transportType))
    return keys

  def _generateConfigKeyRegistration(self):
    transportType, _, _ = self._keyRegTypes()
    if not transportType:
      return []
    keys = []
    for key in self.profileKeys:
      keys.append('@"%s" : [%s class]' % (key, transportType))
    return keys


