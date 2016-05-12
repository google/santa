platform :osx, "10.9"

inhibit_all_warnings!

def mol_pods
  pod 'MOLCertificate'
  pod 'MOLCodesignChecker'
end

def fmdb_pod
  pod 'FMDB'

  # This is necessary to get FMDB to not NSLog stuff.
  post_install do |installer|
    installer.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
        if config.name != 'Release' then
          break
        end

        config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] ||= ''
        config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] <<= "NDEBUG=1"
      end
    end
  end
end

target :Santa do
  mol_pods
end

target :santad do
  mol_pods
  fmdb_pod
end

target :santactl do
  mol_pods
  fmdb_pod
end

target :LogicTests do
  mol_pods
  fmdb_pod
  pod 'OCMock'
end
