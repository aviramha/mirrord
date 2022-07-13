import { Buffer } from "node:buffer";
import { createServer } from "net";
import { open, readFile } from "fs/promises";
import http from "http";
import { getServers, resolveAny, resolve, lookup } from "dns/promises";

async function debug_file_ops() {
  try {
    const readOnlyFile = await open("/var/log/dpkg.log", "r");
    console.log(">>>>> open readOnlyFile ", readOnlyFile);

    let buffer = Buffer.alloc(128);
    let bufferResult = await readOnlyFile.read(buffer);
    console.log(">>>>> read readOnlyFile returned with ", bufferResult);

    const sampleFile = await open("/tmp/node_sample.txt", "w+");
    console.log(">>>>> open file ", sampleFile);

    const written = await sampleFile.write("mirrord sample node");
    console.log(">>>>> written ", written, " bytes to file ", sampleFile);

    let sampleBuffer = Buffer.alloc(32);
    let sampleBufferResult = await sampleFile.read(buffer);
    console.log(">>>>> read ", sampleBufferResult, " bytes from ", sampleFile);

    readOnlyFile.close();
    sampleFile.close();
  } catch (fail) {
    console.error("!!! Failed file operation with ", fail);
  }
}

function debug_request() {
  const options = {
    // hostname: "remote-meow",
    // hostname: "local-meow",
    // hostname: "nginx",
    hostname: "apache",
    // hostname: "localhost",
    // hostname: "google.com",
    port: 80,
    path: "/",
    method: "GET",
  };

  const request = http.request(options, (response) => {
    console.log(`statusCode: ${response.statusCode}`);

    response.on("data", (d) => {
      process.stdout.write(d);
    });
  });

  request.on("error", (error) => {
    console.error(error);
  });

  request.end();
}

let a = lookup("google.com").then((values) => {
  console.log("resolved ", values);
});

let b = lookup("nginx").then((values) => {
  console.log("resolved ", values);
});

// debug_file_ops();

// debug_request();
// debug_listen();

function debug_listen() {
  const server = createServer();
  server.on("connection", handleConnection);
  server.listen(
    {
      host: "localhost",
      port: 80,
    },
    function () {
      console.log(">>>>> server listening to %j", server.address());

      let servers = getServers();
      console.log(">>>>> dns servers ", servers);

      let a = resolve("google.com").then((values) => {
        console.log("resolved ", values);
      });

      let b = resolve("nginx").then((values) => {
        console.log("resolved ", values);
      });
    }
  );

  function handleConnection(conn) {
    var remoteAddress = conn.remoteAddress + ":" + conn.remotePort;
    console.log("new client connection from %s", remoteAddress);
    conn.on("data", onConnData);
    conn.once("close", onConnClose);
    conn.on("error", onConnError);

    function onConnData(d) {
      console.log("connection data from %s: %j", remoteAddress, d.toString());
      conn.write(d);
    }
    function onConnClose() {
      console.log("connection from %s closed", remoteAddress);
    }
    function onConnError(err) {
      console.log("Connection %s error: %s", remoteAddress, err.message);
    }
  }
}
