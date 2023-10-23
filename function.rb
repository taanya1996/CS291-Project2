# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  puts event
  http_method = event['httpMethod']
  uri_path = event['path']
  def valid_json?(json_str)
  	JSON.parse(json_str)
  	return true
  rescue 
  	return false
  end

  
  content_type_matching_key = event['headers'].keys.find{|key| key.downcase == 'Content-type'.downcase}

  if http_method == "POST" and uri_path == '/token'
	#check if the content type is application/json
	#'headers' => { 'Content-Type' => 'application/json' }
		
	if event['headers'][content_type_matching_key] != 'application/json'
		return response(body: nil, status:415)
		
	end
	#check if body exists
	if not event.key?('body')
		return response(body:nil, status:422)
	end

	#check if the request body is not json
	if not valid_json?event['body']
		return response(body:nil, status:422)
			
	end

  	# Generate a token
  	payload = {
    		data: JSON.parse(event['body']),
    		exp: Time.now.to_i + 5,
    		nbf: Time.now.to_i + 2
  	}	
	token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
	body = {'token': token }
	status = 201
	puts status
	return response(body:body, status:status)
	
  elsif  http_method == "GET" and uri_path == '/'
	#Handle get request here
	# 'headers' => { 'Authorization' => "Bearer #{token}"
	if not event['headers'].key?('Authorization')
		return response(body:nil, status: 403)
	end
	auth_header = event['headers']['Authorization']
	if not auth_header.start_with?('Bearer ')
		return response(body:nil, status: 403)
		
	end
	encrypted_token = auth_header[7..-1]
	begin
		decoded_token = JWT.decode(encrypted_token, ENV['JWT_SECRET'], true, algorithm:'HS256')
	rescue JWT::ImmatureSignature ,  JWT::ExpiredSignature => e
		return response(body:nil, status: 401)
	rescue JWT::DecodeError => e
		return response(body:nil, status: 403)	
	end	
 	payload = decoded_token[0]
	
	curr_time = Time.now.to_i

	#if payload['nbf']>curr_time or payload['exp']<curr_time
	#	return response(body:nil, status:401)
	#end	
	
	return response(body:payload['data'], status:200)
	

  
  elsif uri_path == '/' or  uri_path == "/token"
	#return 405
	return response(body:nil, status:405)
  else
	#respond with 404
	return response(body:nil, status: 404)
  end
	  
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
