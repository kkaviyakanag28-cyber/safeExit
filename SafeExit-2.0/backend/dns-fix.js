const dns = require('dns');

dns.setServers(['8.8.8.8', '1.1.1.1']);

console.log('MongoDB DNS configured');