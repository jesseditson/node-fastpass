// FastPass
// ---
// A node.js module for setting up getsatisfaction fastpass
// http://getsatisfaction.com/corp/help/fastpass-implementation.html

// Dependencies
// ---
var fs = require('fs'),
    crypto = require('crypto'),
    querystring = require('querystring'),
    url = require('url')

// Local Variables
// ---
var scriptTemplate = fs.readFileSync(__dirname + '/script.html','utf8')

// FastPass Module
// ---
// accepts an options object, where options are:
// domain - optional, your domain, defaults to getsatisfaction.com
// consumer_key - required, the consumer key given to you by getSatisfaction
// consumer_secret - required, the consumer secret given to you by getSatisfaction
// email - optional during setup, the fastpass user's email
// name - optional during setup, the fastpass user's nickname
// unique_identifier - optional during setup, the users' unique ID. (must always stay the same in your system)
// is_secure - optional, if set to true, will use https. defaults to false.
// private_fields - optional, an object of key/value pairs to send along with the user. defaults to an empty object.
var FastPass = module.exports = function(options){
  // validate that we have an options object
  if(!options || (typeof options != 'object' && !Array.isArray(options))){
    throw new Error("FastPass requires an options object to be passed.")
    return false
  }
  // validate required options exist
  ['consumer_key','consumer_secret'].forEach(function(requiredOption){
    // checking for the key should be sufficient, they should all be strings, but no need for type checking.
    if(!options[requiredOption]){
      throw new Error("FastPass requires the "+requiredOption+" option.")
      return false
    }
  })
  // set up options
  this.options = {
    domain : options.domain || "getsatisfaction.com",
    consumer_key : options.consumer_key,
    consumer_secret : options.consumer_secret,
    email : options.email || false,
    name : options.name || false,
    unique_identifier : options.unique_identifier || false,
    is_secure : options.is_secure || false,
    private_fields : options.private_fields || {}
  }
}

// **url**
// generates a fastpass url with the provided key and secret.
// optionally takes an options object to override options for this url.
// calls back with `err`,`url`
// no required options unless instantiated without one of the following:
// email - required unless passed during setup, the fastpass user's email
// name - required unless passed during setup, the fastpass user's nickname
// unique_identifier - required unless passed during setup, the users' unique ID. (must always stay the same in your system)
FastPass.prototype.url = function(options,callback){
  // make options optional.
  if(!callback && typeof options === 'function'){
    callback = options
    options = {}
  }
  validateOptions(['email','name','unique_identifier'],options,this.options,function(err,options){
    // throw errors if we've got em
    if(err){
      callback(new Error("Cannot call url without required option "+err.message))
      return false
    }
    // set up query params
    var params = {
      email : options.email,
      name : options.name,
      uid : options.unique_identifier
    }
    // merge in private fields
    for(var field in options.private_fields){
      params[field] = options.private_fields[field]
    }
    // set up variables for the request
    var uri = (options.is_secure ? 'https' : 'http') + '://' + options.domain + '/fastpass'
    // get an oAuth url
    var oAuthUrl = oAuthRequestUrl({key : options.consumer_key, secret : options.consumer_secret},null,"GET",uri,params)
    callback(null,oAuthUrl)
  })
}
// **image**
// Generates a FastPass IMG tag. This integration method is likely to be deprecated, unless strong use cases are presented. Be warned.
// takes same options as **script**, below.
FastPass.prototype.image = function(options,callback){
  // make options optional.
  if(!callback && typeof options === 'function'){
    callback = options
    options = {}
  }
  this.url(options,function(err,url){
    var image = '<img src="'+escapeHtml(url)+'" alt=""/>'
    callback(err,image)
  })
}

// **script**
// Generates a FastPass SCRIPT tag. The script will automatically rewrite all GetSatisfaction URLs to include a 'fastpass' query param with a signed fastpass URL.
// optionally takes an options object to override options for this script tag.
// calls back with 
// no required options unless called without one of the following:
// email - required unless passed during setup, the fastpass user's email
// name - required unless passed during setup, the fastpass user's nickname
// unique_identifier - required unless passed during setup, the users' unique ID. (must always stay the same in your system)
FastPass.prototype.script = function(options,callback){
  // make options optional.
  if(!callback && typeof options === 'function'){
    callback = options
    options = {}
  }
  this.url(options,function(err,url){
    if(err){
      callback(err)
      return false
    }
    var script = scriptTemplate.replace(/<!--[\s\S]*?-->/g,'').replace('[[url]]',escapeHtml(url)).replace('[[domain]]',this.options.domain)
    callback(null,script)
  })
}

// oAuth Helpers
// ---

// **oauthRequest**
// does an oAuth request
var oAuthRequestUrl = function(consumer,token,http_method,http_url,parameters){
  var options = {
    oauth_version : "1.0",
    oauth_nonce : generateNonce(),
    oauth_timestamp : Math.round(new Date().getTime()/1000),
    oauth_consumer_key : consumer.key
  }
  for(var p in parameters){
    // allow overrides of params
    options[p] = parameters[p]
  }
  if(token){
    options.oauth_token = token.key
  }
  options.oauth_signature_method = "HMAC-SHA1"
  options.oauth_signature = getSignature(consumer,token,http_method,http_url,options)
  var query = {}
  for(var o in options){
    query[rfc3986(o)] = options[o]
  }
  return normalizeUrl(http_url) + "?" + querystring.stringify(query)
}

// **generate nonce**
// generates an oauth nonce
var generateNonce = function(){
  var nonce = crypto.createHash('md5')
  nonce.update(new Date().getTime() + (Math.random()*1000).toString(), 'utf8')
  return nonce.digest('hex')
}

// **getSignature**
// generates an oauth signature.
var getSignature = function(consumer,token,method,httpurl,params){
  var baseString = getSignatureBaseString(method,httpurl,params),
      key = [consumer.secret,token ? token.secret : ""].map(rfc3986).join('&')
  //console.log(baseString," :::: ",key)
  return sha1(baseString,key)
}

// **signature base string**
// generates signature base string
var getSignatureBaseString = function(method,httpurl,params){
  // convert signable params to querystring object
  var signable_params_unsorted = {},
      signable_params = {}
  for(var p in params){
    if(p == 'oauth_signature') continue
    signable_params_unsorted[rfc3986(p)] = params[p]
  }
  // sort via natural compare
  Object.keys(signable_params_unsorted).sort(alphanum).forEach(function(key){
    signable_params[key] = signable_params_unsorted[key]
  })
  signable_params = querystring.stringify(signable_params)
  return [
      method.toUpperCase(),
      normalizeUrl(httpurl),
      signable_params
    ].map(rfc3986).join('&')
}

// **normalize url**
var normalizeUrl = function(httpurl){
  // parse the url, add the port
  var parsedUrl = url.parse(httpurl)
  return parsedUrl.protocol + "//" + parsedUrl.host + parsedUrl.pathname
}

// **sha1**
// quicker sha1s
var sha1 = function(str,key){
  var sha = crypto.createHmac('sha1',key)
  sha.update(str)
  return sha.digest('base64')
}

// Helpers
// ---

// **escapehtml**
// escapes html characters (for urls)
var escapeHtml = function(unsafe) {
  return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;")
}

// **rfc3986**
// encodes a string via rfc3986
// overrides the native querystring escape.
var rfc3986 = querystring.escape = function (string){
   return encodeURIComponent(string)
       .replace(/!/g,'%21')
       .replace(/\*/g,'%2A')
       .replace(/\(/g,'%28')
       .replace(/\)/g,'%29')
       .replace(/'/g,'%27')
       .replace(/%7E/g,'~')
       .replace(/\+/g,' ')
}

// **validate options**
// takes an array, an object, and optionally a default object.
// fills in options from the default object or calls back with an error if option does not exist.
var validateOptions = function(array,options,defaults,callback){
  var key, i=0, len=array.length
  for(i;i<len;i++){
    key = array[i]
    if(!options[key] && !defaults[key]){
      // blow up and return if missing from both defaults and options
      callback(new Error(key))
      return false
    } else {
      defaults[key] = options[key] || defaults[key]
    }
  }
  // success
  callback(null,defaults)
}

// **alphanum**
// Natural sorting algorithm
// Thanks to David Koelle's perl algo (http://www.davekoelle.com/alphanum.html),
// and Brian Huisman for the js port: http://my.opera.com/GreyWyvern/blog/show.dml/1671288
function alphanum(a, b) {
  function chunkify(t) {
    var tz = [], x = 0, y = -1, n = 0, i, j;

    while (i = (j = t.charAt(x++)).charCodeAt(0)) {
      var m = (i == 46 || (i >=48 && i <= 57));
      if (m !== n) {
        tz[++y] = "";
        n = m;
      }
      tz[y] += j;
    }
    return tz;
  }

  var aa = chunkify(a);
  var bb = chunkify(b);

  for (x = 0; aa[x] && bb[x]; x++) {
    if (aa[x] !== bb[x]) {
      var c = Number(aa[x]), d = Number(bb[x]);
      if (c == aa[x] && d == bb[x]) {
        return c - d;
      } else return (aa[x] > bb[x]) ? 1 : -1;
    }
  }
  return aa.length - bb.length;
}