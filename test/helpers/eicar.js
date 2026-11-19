/* jslint node: true */
'use strict';

//
//  EICAR test files, built at run time so this repository never contains
//  the test string itself (which would make the checkout trip scanners).
//  Includes a minimal "stored" (uncompressed) ZIP writer, enough for clamd to
//  unpack plain and nested archives.
//

const zlib = require('zlib');
const crypto = require('crypto');

const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

function eicar() {
    //  two halves, joined at run time
    const a = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR';
    const b = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const buf = Buffer.from(a + b, 'ascii');
    if (crypto.createHash('sha256').update(buf).digest('hex') !== EICAR_SHA256) {
        throw new Error('EICAR test string is wrong');
    }
    return buf;
}

//  |entries|: [ { name, data: Buffer } ]
function storedZip(entries) {
    const locals = [];
    const centrals = [];
    let offset = 0;

    entries.forEach(({ name, data }) => {
        const nameBuf = Buffer.from(name, 'ascii');
        const crc = zlib.crc32(data);

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0); //  local file header
        local.writeUInt16LE(10, 4); //  version needed
        local.writeUInt16LE(0, 6); //  flags
        local.writeUInt16LE(0, 8); //  method: stored
        local.writeUInt16LE(0, 10); //  time
        local.writeUInt16LE(0x21, 12); //  date: 1980-01-01
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(data.length, 18);
        local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(nameBuf.length, 26);
        local.writeUInt16LE(0, 28);
        locals.push(local, nameBuf, data);

        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0); //  central directory header
        central.writeUInt16LE(20, 4); //  version made by
        central.writeUInt16LE(10, 6);
        central.writeUInt16LE(0, 8);
        central.writeUInt16LE(0, 10);
        central.writeUInt16LE(0, 12);
        central.writeUInt16LE(0x21, 14);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(data.length, 20);
        central.writeUInt32LE(data.length, 24);
        central.writeUInt16LE(nameBuf.length, 28);
        //  extra, comment, disk, internal attrs: 0
        central.writeUInt32LE(0, 38); //  external attrs
        central.writeUInt32LE(offset, 42);
        centrals.push(central, nameBuf);

        offset += local.length + nameBuf.length + data.length;
    });

    const centralBuf = Buffer.concat(centrals);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0); //  end of central directory
    end.writeUInt16LE(entries.length, 8);
    end.writeUInt16LE(entries.length, 10);
    end.writeUInt32LE(centralBuf.length, 12);
    end.writeUInt32LE(offset, 16);

    return Buffer.concat([...locals, centralBuf, end]);
}

module.exports = { EICAR_SHA256, eicar, storedZip };
