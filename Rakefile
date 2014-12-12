require 'timeout'

WORKSPACE       = 'Santa.xcworkspace'
DEFAULT_SCHEME  = 'All'
OUTPUT_PATH     = 'build'
PLISTS          = ['Source/SantaGUI/Resources/Santa-Info.plist',
                   'Source/santad/Resources/santad-Info.plist',
                   'Source/santa-driver/Resources/santa-driver-Info.plist',
                   'Source/santactl/Resources/santactl-Info.plist']
XCODE_DEFAULTS  = "-workspace #{WORKSPACE} -scheme #{DEFAULT_SCHEME} -derivedDataPath #{OUTPUT_PATH} -parallelizeTargets"

task :default do
  system("rake -sT")
end

def run_and_output_on_fail(cmd)
  output=`#{cmd} 2>&1`
  if not $?.success?
    raise output
  end
end

def run_and_output_with_color(cmd)
  output=`#{cmd} 2>&1`

  has_output = false
  output.scan(/((Test Suite|Test Case|Executed).*)$/) do |match|
    has_output = true
    out = match[0]
    if out.include?("passed")
      puts "\e[32m#{out}\e[0m"
    elsif out.include?("failed")
      puts "\e[31m#{out}\e[0m"
    else
      puts out
    end
  end

  if not has_output
    raise output
  end
end

task :init do
  unless File.exists?(WORKSPACE) and File.exists?('Pods')
    puts "Workspace is missing, running 'pod install'"
    system "pod install" or raise "CocoaPods is not installed. Install with 'sudo gem install cocoapods'"
  end
end

task :remove_existing do
  system 'sudo rm -rf /santa-driver.kext'
  system 'sudo rm -rf /Applications/Santa.app'
  system 'sudo rm /usr/libexec/santad'
  system 'sudo rm /usr/sbin/santactl'
end

desc "Clean"
task :clean => :init do
  puts "Cleaning"
  run_and_output_on_fail("xcodebuild #{XCODE_DEFAULTS} clean")
  FileUtils.rm_rf(OUTPUT_PATH)
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
    run_and_output_on_fail("xcodebuild #{XCODE_DEFAULTS} -configuration #{config} build")
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
    system "sudo cp -r #{OUTPUT_PATH}/Products/#{config}/santa-driver.kext /"
    system "sudo cp -r #{OUTPUT_PATH}/Products/#{config}/Santa.app /Applications"
    system "sudo cp #{OUTPUT_PATH}/Products/#{config}/santad /usr/libexec"
    system "sudo cp #{OUTPUT_PATH}/Products/#{config}/santactl /usr/sbin"
  end
end

# Tests
namespace :tests do
  desc "Tests: Logic"
  task :logic => [:init] do
    puts "Running logic tests"
    run_and_output_with_color("xcodebuild #{XCODE_DEFAULTS} test")
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
  system "sudo kextunload /santa-driver.kext 2>/dev/null"
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
  system "sudo kextload /santa-driver.kext"
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

# Versioning
desc "Update version, version should be of the form rake version[\\d{1,4}.\\d{1,2}(?:.\\d{1,2})?]"
task :version, :version do |t, args|
  response = args[:version]

  unless response =~ /^\d{1,4}\.\d{1,2}(?:\.\d{1,2})?$/
    raise "Version number must be of form: xxxx.xx[.xx]. E.g: rake version[1.0.2], rake version[1.7]"
  end

  system "sed -i -e 's/MODULE_VERSION = .*;/MODULE_VERSION = #{response};/g' Santa.xcodeproj/project.pbxproj"

  PLISTS.each do |plist|
    system "defaults write $PWD/#{plist} CFBundleVersion #{response}"
    system "defaults write $PWD/#{plist} CFBundleShortVersionString #{response}"
    system "plutil -convert xml1 $PWD/#{plist}"
  end

  puts "Updated version to #{response}"
end
