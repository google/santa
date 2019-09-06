
def common_pods
   pod 'MOLXPCConnection'
   pod 'MOLCodesignChecker'
   pod 'FMDB'
   pod 'MOLCertificate'
   pod 'OCMock'
   pod 'MOLAuthenticatingURLSession'
   pod 'MOLFCMClient'
end

project './Santa.xcodeproj'

project = Xcodeproj::Project.open "./Santa.xcodeproj"
project.targets.each do |t|
  if t.name == "santa-driver"
      next
  end
  target t.name do
      common_pods
  end
end
