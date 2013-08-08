Pod::Spec.new do |s|
  s.name     = 'SanitizeTidy'
  s.version  = '0.1.0'
  s.license  = 'Simplified BSD License'
  s.summary  = "libtidy Objective-C wrapper with sanitize functionality"
  s.homepage = 'https://github.com/kswchoo/SanitizeTidy'
  s.author   = { 'Kevin Sungwoo Choo' => 'kswchoo@gmail.com' }
  s.source   = { :git => 'https://github.com/kswchoo/SanitizeTidy.git', :tag => 'v0.1.0' }
  s.source_files = 'SanitizeTidy/SanitizeTidy.{h,m}', 'SanitizeTidy/sanitizer.{c,h}', 'libtidy/**/*.{c,h}'
end
