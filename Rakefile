WORKSPACE           = 'Santa.xcworkspace'
TEAMID_CONFIG       = 'Source/TeamID.xcconfig'
DEFAULT_SCHEME      = 'All'
OUTPUT_PATH         = 'Build'
BINARIES            = ['Santa.app', 'santa-driver.kext']
DSYMS               = ['Santa.app.dSYM', 'santa-driver.kext.dSYM', 'santad.dSYM', 'santactl.dSYM']
XCPRETTY_DEFAULTS   = '-sc'
XCODEBUILD_DEFAULTS = "-workspace #{WORKSPACE} -derivedDataPath #{OUTPUT_PATH} -parallelizeTargets"

$DISABLE_XCPRETTY   = false

task :default do
  system("rake -sT")
end

def xcodebuild(opts)
  command = "xcodebuild #{XCODEBUILD_DEFAULTS} #{opts}"
  if not $DISABLE_XCPRETTY
    command << " | xcpretty #{XCPRETTY_DEFAULTS} && exit ${PIPESTATUS[0]}"
  end

  if system command
    puts "\e[32mPass\e[0m"
  else
    raise "\e[31mFail\e[0m"
  end
end

def xcodebuilddir
  if not $xcode_build_dir
    output = `xcodebuild #{XCODEBUILD_DEFAULTS} -scheme All -showBuildSettings`
    if match = output.match(/BUILD_DIR = (.*)/)
        $xcode_build_dir = match.captures.first
        puts "Found Xcode build dir #{$xcode_build_dir}"
    end
  end
  $xcode_build_dir
end

task :init do
  unless File.exists?(WORKSPACE) and File.exists?('Pods')
    puts "Pods missing, running 'pod install'"
    system "pod install" or raise "CocoaPods is not installed. Install with 'sudo gem install cocoapods'"
  end
  unless File.exists?(TEAMID_CONFIG) and File.foreach(TEAMID_CONFIG).grep(/SANTA_DEVELOPMENT_TEAM/).any?
    puts "#{TEAMID_CONFIG} is missing or doesn't contain a SANTA_DEVELOPMENT_TEAM line, attempting to fix"
    output = `/usr/bin/security find-certificate -c "Mac Developer" -p 2>&1 | /usr/bin/openssl x509 -inform pem -text 2>&1`
    teamid = output[/Subject:.+OU=(\w+).+/, 1]
    if teamid.nil? or teamid.empty?
      raise "Unable to determine Team Identifier. Please manually write your Team Identifier to #{TEAMID_CONFIG}."
    end
    File.open(TEAMID_CONFIG, 'w') { |f| f.write("SANTA_DEVELOPMENT_TEAM = #{teamid}") }
    puts "Wrote team identifier #{teamid} to #{TEAMID_CONFIG}. If this is incorrect please fix manually"
  end
  unless system 'xcpretty -v >/dev/null 2>&1'
    puts "xcpretty is not installed. Install with 'sudo gem install xcpretty'"
    $DISABLE_XCPRETTY = true
  end
end

task :remove_existing do
  system 'sudo rm -rf /Library/Extensions/santa-driver.kext'
  system 'sudo rm -rf /Applications/Santa.app'
end

desc "Clean"
task :clean => :init do
  puts "Cleaning"
  FileUtils.rm_rf(OUTPUT_PATH)
  xcodebuild("-scheme All clean")
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
    system 'sudo cp conf/com.google.santagui.plist /Library/LaunchAgents'
    system 'sudo cp conf/com.google.santa.asl.conf /etc/asl'
    Rake::Task['build:build'].invoke(config)
    puts "Installing with configuration: #{config}"
    Rake::Task['remove_existing'].invoke()
    system "sudo cp -r #{xcodebuilddir}/#{config}/santa-driver.kext /Library/Extensions"
    system "sudo cp -r #{xcodebuilddir}/#{config}/Santa.app /Applications"
  end
end

# Dist
task :dist do
  desc "Create distribution folder"

  Rake::Task['clean'].invoke()
  Rake::Task['build:build'].invoke("Release")

  dist_path = "santa-#{`defaults read #{xcodebuilddir}/Release/santa-driver.kext/Contents/Info.plist CFBundleVersion`.strip}"

  FileUtils.rm_rf(dist_path)

  FileUtils.mkdir_p("#{dist_path}/binaries")
  FileUtils.mkdir_p("#{dist_path}/conf")
  FileUtils.mkdir_p("#{dist_path}/dsym")

  BINARIES.each do |x|
    FileUtils.cp_r("#{xcodebuilddir}/Release/#{x}", "#{dist_path}/binaries")
  end

  DSYMS.each do |x|
    FileUtils.cp_r("#{xcodebuilddir}/Release/#{x}", "#{dist_path}/dsym")
  end


  Dir.glob("Conf/*") {|x| File.directory?(x) or FileUtils.cp(x, "#{dist_path}/conf")}

  puts "Distribution folder #{dist_path} created"
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
    FileUtils.mkdir_p("/tmp/santa_kerneltests_tmp")
    begin
      puts "\033[?25l\033[12h"  # hide cursor
      puts "Running kernel tests"
      system "cd /tmp/santa_kerneltests_tmp && sudo #{xcodebuilddir}/Debug/KernelTests"
    rescue Exception
    ensure
      puts "\033[?25h\033[12l\n\n"  # unhide cursor
      FileUtils.rm_rf("/tmp/santa_kerneltests_tmp")
      Rake::Task['unload_kext'].execute
    end
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
  system "launchctl unload /Library/LaunchAgents/com.google.santagui.plist 2>/dev/null"
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
  system "launchctl load /Library/LaunchAgents/com.google.santagui.plist 2>/dev/null"
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
