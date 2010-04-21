require 'sinatra'
require 'lib/rack/oauth2/assertion_profile'

use Rack::OAuth2::AssertionProfile, {:shared_secret => "ok1BDh9Mq+LtRmk0hPZMplJ+e2EFZQkC2T9AueDfo2Q=",
					                           :audience => "https://blossom.southworksinc.com",
					                           :scope => "https://blossom-oauth.accesscontrol.windows.net/WRAPv0.9",
                                     :issuer => "https://blossom-oauth.accesscontrol.windows.net/"}

run Sinatra::Application