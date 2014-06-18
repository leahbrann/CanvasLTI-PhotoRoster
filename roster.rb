require 'sinatra'
require 'dotenv'
require 'ims/lti'
require 'oauth/request_proxy/rack_request'
require 'uri'
require 'httparty'

Dotenv.load

set :protection, :except => :frame_options

OAUTH_10_SUPPORT = true

# the consumer keys/secrets
$oauth_creds = {"#{ENV['CONSUMER_KEY']}" => "#{ENV['CONSUMER_SECRET']}"}

def show_error(message)
  @message = message
end

def authorize!
  if key = params['oauth_consumer_key']
    if secret = $oauth_creds[key]
      @tp = IMS::LTI::ToolProvider.new(key, secret, params)
    else
      @tp = IMS::LTI::ToolProvider.new(nil, nil, params)
      @tp.lti_msg = "Your consumer didn't use a recognized key."
      show_error "Consumer key wasn't recognized"
      return false
    end
  else
    show_error "No consumer key"
    return false
  end

  if !@tp.valid_request?(request)
    show_error "The OAuth signature was invalid"
    return false
  end

  if Time.now.utc.to_i - @tp.request_oauth_timestamp.to_i > 60*60
    show_error "Your request is too old."
    return false
  end

  @username = @tp.username

  return true
end

# The url for launching the tool
# It will verify the OAuth signature
post '/courses' do
  return erb :error unless authorize!

     # normal tool launch without grade write-back
    signature = OAuth::Signature.build(request, :consumer_secret => @tp.consumer_secret)

    @signature_base_string = signature.signature_base_string
    @secret = signature.send(:secret)
  

  courses_api = "#{ENV['CANVAS_URL']}/api/v1/courses?"
  courses = HTTParty.get courses_api, :query => {:access_token => "#{ENV['CANVAS_TOKEN']}", :as_user_id => params['custom_canvas_user_id'] }
  @coursestaught = courses.select{|course| course["enrollments"].flat_map{|x| x["type"]}.include? "teacher"}
    
  erb :layout do
    erb :success
  end  

end

get '/courses/:course_id' do
   @course = "#{params[:course_id]}"
   @course_title = HTTParty.get("#{ENV['CANVAS_URL']}/api/v1/courses/#{@course}?access_token=#{ENV['CANVAS_TOKEN']}")["name"]
   course_enrollment_api = ("#{ENV['CANVAS_URL']}/api/v1/courses/#{@course}/users?access_token=#{ENV['CANVAS_TOKEN']}&enrollment_type=student")
   @course_enrollments = HTTParty.get(course_enrollment_api)
   @photos_path = "#{ENV['PHOTOS_PATH']}"

   erb :layout do
      erb :course
   end
end

get '/stylesheet.css' do
  scss :'sass/stylesheet'
end

post '/signature_test' do
  erb :proxy_setup
end

post '/proxy_launch' do
  uri = URI.parse(params['launch_url'])

  if uri.port == uri.default_port
    host = uri.host
  else
    host = "#{uri.host}:#{uri.port}"
  end

  consumer = OAuth::Consumer.new(params['lti']['oauth_consumer_key'], params['oauth_consumer_secret'], {
      :site => "#{uri.scheme}://#{host}",
      :signature_method => "HMAC-SHA1"
  })

  path = uri.path
  path = '/' if path.empty?

  @lti_params = params['lti'].clone
  if uri.query != nil
    CGI.parse(uri.query).each do |query_key, query_values|
      unless @lti_params[query_key]
        @lti_params[query_key] = query_values.first
      end
    end
  end

  path = uri.path
  path = '/' if path.empty?

  proxied_request = consumer.send(:create_http_request, :post, path, @lti_params)
  signature = OAuth::Signature.build(proxied_request, :uri => params['launch_url'], :consumer_secret => params['oauth_consumer_secret'])

  @signature_base_string = signature.signature_base_string
  @secret = signature.send(:secret)
  @oauth_signature = signature.signature

  erb :proxy_launch
end

get '/tool_config.xml' do
  host = request.scheme + "://" + request.host_with_port
  url = (params['signature_proxy_test'] ? host + "/signature_test" : host + "/courses")
  tc = IMS::LTI::ToolConfig.new(:title => "Photo Roster", :launch_url => url)
  tc.description = ""
  tc.set_ext_params("canvas.instructure.com", {"privacy_level" => "public"})
  tc.set_ext_param("canvas.instructure.com", "user_navigation", {"enabled" => "true", "text" => "Photo Roster"})
  headers 'Content-Type' => 'text/xml'
  tc.to_xml(:indent => 4)
end
