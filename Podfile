
def common_pods
   pod 'MOLXPCConnection'
   pod 'MOLCodesignChecker'
   pod 'FMDB'
   pod 'MOLCertificate'
   pod 'OCMock'
end

project './Santa.xcodeproj'

project = Xcodeproj::Project.open "./Santa.xcodeproj"
project.targets.each do |t|
  target t.name do
      common_pods
  end
end
