local kong = kong
local Log4jKongWaf = {
  PRIORITY = 20000,
  VERSION  = "0.1.0"
}

--- Internal function to handle the check of strings against the List of IOC Strings
local function checkIOCStrings(input)
    local cve_found = 0
    local iocList = {
                "${jndi:ldap:/",
		"${jndi:rmi:/",
		"${jndi:ldaps:/",
		"${jndi:dns:/",
		"/$%7bjndi:",
		"%24%7bjndi:",
		"$%7Bjndi:",
		"%2524%257Bjndi",
		"%2F%252524%25257Bjndi%3A",
		"${jndi:${lower:",
		"${::-j}${",
		"${jndi:nis",
		"${jndi:nds",
		"${jndi:corba",
		"${jndi:iiop",
		"${${env:BARFOO:-j}",
		"${::-l}${::-d}${::-a}${::-p}",
		"${base64:JHtqbmRp",
		"/Basic/Command/Base64/",
    }

    for index, pattern in pairs(iocList) do
      if (type(input) == "string") then
         if ( string.match(input,'"'..pattern..'"') ~= nil ) then
            cve_found = 1
         end
         if (string.match(input,"${%w*:%w*") ~= nil) then
            cve_found = 1
        end
      elseif(type(input) == "table") then
            for i, value in pairs(input) do
                if string.match(value,'"'..pattern..'"') ~= nil then
                    cve_found = 1
                 end
                 if string.match(value,"${%w*:%w*") ~= nil then
                    cve_found = 1
                end
            end
       end
    end
    return cve_found
end


function Log4jKongWaf:rewrite(config)
    if conf.enabled then
        local request_method = kong.request.get_method()
        local headers = kong.request.get_headers()
        local body = kong.request.get_raw_body()
        local uri = kong.request.get_path_with_query()
         --- Validates an incoming request body and checks it for IOCs of CVE2021-44228
	 --- Validates an incoming request and checks all Headers as well as the URI for IOCs 
         --- of CVE2021-44228
        if (checkIOCStrings(body) == 1 or checkIOCStrings(uri) == 1 or checkIOCStrings(headers) == 1) then
	   return kong.response.error(403, "WAF Activated",{["Content-Type"] = "text/html"})
	end
    end
end
