/* jslint node: true */
'use strict';

//
//  ENiGMA½ file scanners: ClamAV (clamd, zINSTREAM) and VirusTotal hash
//  lookup, for fileBase.scanning (#291). See README.md.
//
//  Registers two scanners by name, |clamav| and |virustotal|, through the
//  registerFileScanners() export that both the BBS (at startup) and
//  oputil fb scan --virus-scan call. Nothing happens at require time: oputil
//  requires this file just to call that export.
//

const clamav = require('./lib/clamav.js');
const virustotal = require('./lib/virustotal.js');

exports.moduleInfo = {
    name: 'AV Scanners',
    desc: 'ClamAV (clamd) and VirusTotal hash lookup file scanners',
    author: 'NuSkooler',
    packageName: 'codes.l33t.enigma.av_scanners',
};

exports.registerFileScanners = (registry, cb) => {
    registry.registerScanner(clamav.SCANNER_NAME, clamav.createClamAvScanner());
    registry.registerScanner(
        virustotal.SCANNER_NAME,
        virustotal.createVirusTotalScanner()
    );
    return cb(null);
};
