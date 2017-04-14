platform :osx, "10.9"

inhibit_all_warnings!

target :Santa do
  pod 'MOLCertificate'
  pod 'MOLCodesignChecker'
end

target :santad do
  pod 'FMDB'
  pod 'MOLCertificate'
  pod 'MOLCodesignChecker'
  target :santabs do
    pod 'FMDB'
    pod 'MOLCertificate'
    pod 'MOLCodesignChecker'
  end
end

target :santactl do
  pod 'FMDB'
  pod 'MOLAuthenticatingURLSession'
  pod 'MOLCertificate'
  pod 'MOLCodesignChecker'
  pod 'MOLFCMClient', '~> 1.3'
end

target :LogicTests do
  pod 'FMDB'
  pod 'MOLAuthenticatingURLSession'
  pod 'MOLCertificate'
  pod 'MOLCodesignChecker'
  pod 'OCMock'
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      if config.name != 'Release' then
        break
      end

      # This is necessary to get FMDB to not NSLog stuff.
      config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] ||= ''
      config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] <<= "NDEBUG=1"

      # Enable more compiler optimizations.
      config.build_settings['GCC_OPTIMIZATION_LEVEL'] = 'fast'
      config.build_settings['LLVM_LTO'] = 'YES'
    end
  end
end

