def run_command(name, cmd, **kwargs):
  native.genrule(
    name = '%s__gen' % name,
    executable = True,
    outs = [ '%s.sh' % name ],
    cmd = 'echo \'#!/bin/bash\' > $@ && echo \'%s\' >> $@' % cmd,
    **kwargs
  )
  native.sh_binary(
    name = name,
    srcs = [ '%s.sh' % name ],
  )
