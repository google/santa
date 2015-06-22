require 'timeout'

WORKSPACE           = 'Santa.xcworkspace'
DEFAULT_SCHEME      = 'All'
OUTPUT_PATH         = 'Build'
DIST_PATH           = 'Dist'
BINARIES            = ['Santa.app', 'santa-driver.kext']
XCPRETTY_DEFAULTS   = '-sc'
XCODEBUILD_DEFAULTS = "-workspace #{WORKSPACE} -derivedDataPath #{OUTPUT_PATH} -parallelizeTargets"

task :default do
  system("rake -sT")
end

def xcodebuild(opts)
  if system "xcodebuild #{XCODEBUILD_DEFAULTS} #{opts} | " \
      "xcpretty #{XCPRETTY_DEFAULTS} && " \
      "exit ${PIPESTATUS[0]}"
    puts "\e[32mPass\e[0m"
  else
    raise "\e[31mFail\e[0m"
  end
end

task :init do
  unless File.exists?(WORKSPACE) and File.exists?('Pods')
    puts "Pods missing, running 'pod install'"
    system "pod install" or raise "CocoaPods is not installed. Install with 'sudo gem install cocoapods'"
  end
  unless system 'xcpretty -v >/dev/null 2>&1'
    puts "xcpretty is not installed. Install with 'sudo gem install xcpretty'"
  end
end

task :remove_existing do
  system 'sudo rm -rf /Library/Extensions/santa-driver.kext'
  system 'sudo rm -rf /Applications/Santa.app'
end

desc "Clean"
task :clean => :init do
  puts "Cleaning"
  xcodebuild("-scheme All clean")
  FileUtils.rm_rf(OUTPUT_PATH)
  FileUtils.rm_rf(DIST_PATH)
end

# Build
namespace :build do
  desc "Build: Debug"
  task :debug do
    Rake::Task['build:build'].invoke("Debug")
  end

  desc "Build: Release"
  task :release do
    Rake::Task['build:build'].invoke("Release")
  end

  task :build, [:configuration] => :init do |t, args|
    config = args[:configuration]
    puts "Building with configuration: #{config}"
    xcodebuild("-scheme All -configuration #{config} build")
  end
end


# Install
namespace :install do
  desc "Install: Debug"
  task :debug do
    Rake::Task['install:install'].invoke("Debug")
  end

  desc "Install: Release"
  task :release do
    Rake::Task['install:install'].invoke("Release")
  end

  task :install, [:configuration] do |t, args|
    config = args[:configuration]
    system 'sudo cp conf/com.google.santad.plist /Library/LaunchDaemons'
    system 'sudo cp conf/com.google.santasync.plist /Library/LaunchDaemons'
    system 'sudo cp conf/com.google.santagui.plist /Library/LaunchAgents'
    system 'sudo cp conf/com.google.santa.asl.conf /etc/asl'
    Rake::Task['build:build'].invoke(config)
    puts "Installing with configuration: #{config}"
    Rake::Task['remove_existing'].invoke()
    system "sudo cp -r #{OUTPUT_PATH}/Products/#{config}/santa-driver.kext /Library/Extensions"
    system "sudo cp -r #{OUTPUT_PATH}/Products/#{config}/Santa.app /Applications"
  end
end

# Dist
task :dist do
  desc "Create distribution folder"

  Rake::Task['build:build'].invoke("Release")

  FileUtils.rm_rf(DIST_PATH)

  FileUtils.mkdir_p("#{DIST_PATH}/binaries")
  FileUtils.mkdir_p("#{DIST_PATH}/conf")
  FileUtils.mkdir_p("#{DIST_PATH}/dsym")

  BINARIES.each do |x|
    FileUtils.cp_r("#{OUTPUT_PATH}/Products/Release/#{x}", "#{DIST_PATH}/binaries")
    FileUtils.cp_r("#{OUTPUT_PATH}/Products/Release/#{x}.dSYM", "#{DIST_PATH}/dsym")
  end

  Dir.glob("Conf/*") {|x| File.directory?(x) or FileUtils.cp(x, "#{DIST_PATH}/conf")}

  puts "Distribution folder created"
end

# Tests
namespace :tests do
  desc "Tests: Logic"
  task :logic => [:init] do
    puts "Running logic tests"
    xcodebuild("-scheme LogicTests test")
  end

  desc "Tests: Kernel"
  task :kernel do
    Rake::Task['unload'].invoke()
    Rake::Task['install:debug'].invoke()
    Rake::Task['load_kext'].invoke
    timeout = 30
    puts "Running kernel tests with a #{timeout} second timeout"
    begin
      Timeout::timeout(timeout) {
        system "sudo #{OUTPUT_PATH}/Products/Debug/KernelTests"
      }
    rescue Timeout::Error
      puts "ERROR: tests ran for longer than #{timeout} seconds and were killed."
    end
    Rake::Task['unload_kext'].execute
  end
end

# Load/Unload
task :unload_daemon do
  puts "Unloading daemon"
  system "sudo launchctl unload /Library/LaunchDaemons/com.google.santad.plist 2>/dev/null"
end

task :unload_kext do
  puts "Unloading kernel extension"
  system "sudo kextunload -b com.google.santa-driver 2>/dev/null"
end

task :unload_gui do
  puts "Unloading GUI agent"
  system "sudo killall Santa 2>/dev/null"
end

desc "Unload"
task :unload => [:unload_daemon, :unload_kext, :unload_gui]

task :load_daemon do
  puts "Loading daemon"
  system "sudo launchctl load /Library/LaunchDaemons/com.google.santad.plist"
end

task :load_kext do
  puts "Loading kernel extension"
  system "sudo kextload /Library/Extensions/santa-driver.kext"
end

task :load_gui do
  puts "Loading GUI agent"
  system "open /Applications/Santa.app"
end

desc "Load"
task :load => [:load_kext, :load_daemon, :load_gui]

namespace :reload do
  desc "Reload: Debug"
  task :debug do
    Rake::Task['unload'].invoke()
    Rake::Task['install:debug'].invoke()
    Rake::Task['load'].invoke()
  end

  desc "Reload: Release"
  task :release do
    Rake::Task['unload'].invoke()
    Rake::Task['install:release'].invoke()
    Rake::Task['load'].invoke()
  end
end
