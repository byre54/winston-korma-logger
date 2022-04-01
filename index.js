require('dotenv').config()
const path = require('path');
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, json } = format;
const { UDPTransport } = require("udp-transport-winston");
const serverName = require('os').hostname()
const serviceName = process.cwd().split('/').splice(-1).shift()
var PROJECT_ROOT = path.join(__dirname, '..', '..');
const levels = {
  EMERGENCY: 0,
  ALERT: 1,
  CRITICAL: 2,
  ERROR: 3,
  WARNING: 4,
  NOTICE: 5,
  INFO: 6,
  DEBUG: 7,
  DEFAULT: 8,
};
module.exports.intercept = (req,res) => {
  const oldjson= res.json
  res.json = function(theData) {
    req.loggerData = theData
    res.json = oldjson // set function back to avoid the 'double-send'
    return res.json(theData) // just call as normal with theData
  }
}
module.exports.send = (req, res, options) => {
  const logger = createLogger({
    levels: levels,
    format: combine(
      timestamp(),
      json(),
    ),
    transports: [
      new UDPTransport({
        host: options.logServerHost,
        port: parseInt(options.logServerPort),
        level: 'INFO',
      }),
    ],
  });

  let level = 'INFO';
  if (res && res.statusCode) {
    level =
      res.statusCode >= 800
        ? "EMERGENCY"
        : res.statusCode >= 700
          ? "ALERT"
          : res.statusCode >= 600
            ? "CRITICAL"
            : res.statusCode >= 500
              ? "ERROR"
              : res.statusCode >= 400
                ? "WARNING"
                : res.statusCode >= 300
                  ? "NOTICE"
                  : res.statusCode >= 200
                    ? "INFO"
                    : res.statusCode >= 100
                      ? "DEBUG"
                      : "DEFAULT";
  }
  const startTime = new Date(options.receivedTime).getTime()
  const endTime = new Date().getTime()
  const headerHostname = req.headers.host
  const serviceURI = req._parsedUrl.pathname
  const processTime =  endTime - startTime
  const serviceQuery= req._parsedUrl.query
  const originURI = req.originalUrl
  const servicePoint = originURI.split('/').slice(1).shift()
  const log = {
    level: level,
    severity: level,
    serviceName: `${serviceName}-service-${options.logEnvironment}`,
    serviceURI:serviceURI,
    originURI: originURI,
    servicePoint : servicePoint,
    serviceEndpoint : servicePoint+serviceURI,
    serviceQuery:serviceQuery,
    serviceHostname:headerHostname,
    logName: `${serviceName}/logs/${options.logEnvironment}`,
    resource: {
      type: "ocp_instance",
      labels: {
        project_id: serviceName+"-project",
        instance_id: serviceName+"-instance",
        zone: serverName,
      },
    },
    receiveTimestamp: options.receivedTime,
    startTime: startTime,
    endTime: endTime,
    processTime: processTime
  }

  const httpRequest = {};
  if (req) {
    log.httpRequest = httpRequest;
    httpRequest.requestMethod = req.method;
    httpRequest.requestUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
    httpRequest.protocol = `HTTP/${req.httpVersion}`;
    httpRequest.requestSize = req.socket.bytesRead;
    if (typeof req.ip !== 'undefined') {
      httpRequest.remoteIp = req.ip.indexOf(":") >= 0 ? req.ip.substring(req.ip.lastIndexOf(":") + 1) : req.ip;
    } else {
      httpRequest.remoteIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    }
    
    httpRequest.userAgent = req.get("User-Agent");
    httpRequest.referrer = req.get("Referrer") || "DIRECT";
    if (req.body) {
      if (typeof req.body === "object") {
        log.jsonPayload = req.body;
      } else if (typeof req.body === "string") {
        log.textPayload = req.body;
      }
    }
    if (req.query && req.query.visitor_id) {
      log.visitorId = req.query.visitor_id;
    }
  }

  if (res) {
    log.httpRequest = httpRequest;
    httpRequest.status = res.statusCode;
    httpRequest.cacheHit = res.get("X-Cache") || 'MISS';
    httpRequest.cacheLookup = res.get("X-Cache-Lookup")|| 'MISS';
    httpRequest.latency = res.get("X-Response-Time") || processTime;
  }

  if (req.loggerData) {
    if (req.loggerData.body) {
      if (typeof req.loggerData.body === "object") {
        httpRequest.responseSize = JSON.stringify(req.loggerData.body).length;
      } else if (typeof req.loggerData.body === "string") {
        httpRequest.responseSize = req.loggerData.body.length;
      }
    }
    if (req.loggerData.error) {
      log.sourceLocation = getSouceLocation(req.loggerData.error);
    }
  }

  log.message = getMessage(req, res);

  logger.log(log);
  console.log(log)
}

function getMessage(req, res) {
  let messages = new Set();
  if (res) {
    messages.add(res.statusMessage);
  }
  if (req.loggerData) {
    typeof req.loggerData.error === 'undefined' ? messages.add(req.loggerData.message) :messages.add(req.loggerData.error.message) 
  }
  return Array.from(messages).join(" | ");
}

/**
 * Parses and returns info about the call stack.
 */
function getSouceLocation(error) {
  // get call stack, and analyze it
  // get all file, method, and line numbers
  if (!error.stack) return;
  const stacklist = error.stack
    .replace(/^.*[\\/]node_modules[\\/].*$|^.((?!at).)*$|^.*<anonymous>.*$|^.*internal\/timers.js.*$/gm, "")
    .replace(/\n+/g, "\n").split("\n")
    .filter((item, index, array) => {
      if (!!item) {
        return index === array.indexOf(item);
      }
    });

  // stack trace format:
  // http://code.google.com/p/v8/wiki/JavaScriptStackTraceApi
  // do not remove the regex expresses to outside of this method (due to a BUG in node.js)
  var stackReg = /at\s+(.*)\s+\((.*):(\d*):(\d*)\)/gi
  var stackReg2 = /at\s+()(.*):(\d*):(\d*)/gi

  const sources = []
  stacklist.forEach((item) => {
    var sp = stackReg.exec(item) || stackReg2.exec(item)
    if (sp && sp.length === 5) {
      sources.push(
        {
          function: sp[1],
          file: path.relative(PROJECT_ROOT, sp[2]),
          line: sp[3],
          column: sp[4],
        }
      )
    }
  });
  const stack = stacklist.join('\n');
  return { sources, stack };
}
