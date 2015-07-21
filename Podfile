platform :osx, "10.9"

inhibit_all_warnings!

target :santad do
  pod 'FMDB'

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

target :LogicTests do
  pod 'OCMock'
  pod 'FMDB'
end
