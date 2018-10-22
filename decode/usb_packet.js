var util = require("pcap/util");
var Uint64LE = require('int64-buffer').Uint64LE;
var Int64LE = require ('int64-buffer').Int64LE;

function UsbPacket(emitter) {
	this.emitter = emitter;
	this.id = undefined;
	this.type = undefined;
	this.xfer_type = undefined;
	this.epnum = undefined;
	this.devnum = undefined;
	this.busnum = undefined;
	this.flag_setup = undefined;
	this.flag_data = undefined;
	this.ts_sec = undefined;
	this.ts_usec = undefined;
	this.status = undefined;
	this.length = undefined;
	this.len_cap = undefined;
	this.interval = undefined;
	this.start_frame = undefined;
	this.xfer_flags = undefined;
	this.ndesc = undefined;
	this.leftover_data = undefined;
}


UsbPacket.prototype.decode = function(raw_packet, offset) {
	var pos = offset;

	this.id = new Uint64LE(raw_packet.slice(0, 8));
	pos += 8;
	this.type = raw_packet.readUInt8(pos, true);
	pos += 1;
	this.xfer_type = raw_packet.readUInt8(pos, true);
	pos += 1;
	this.epnum = raw_packet.readUInt8(pos, true);
	pos += 1;
	this.devnum = raw_packet.readUInt8(pos, true);
	pos += 1;
	this.busnum = raw_packet.readUInt16LE(pos, true);
	pos += 2;
	this.flag_setup = raw_packet.readInt8(pos, true);
	pos += 1;
	this.flag_data = raw_packet.readInt8(pos, true);
	pos += 1;
	this.ts_sec = new Int64LE(raw_packet.slice(pos, pos + 8));
	pos += 8;
	this.ts_usec = raw_packet.readInt32LE(pos, true);
	pos += 4;
	this.status = raw_packet.readInt32LE(pos, true);
	pos += 4;
	this.length = raw_packet.readUInt32LE(pos, true);
	pos += 4;
	this.len_cap = raw_packet.readUInt32LE(pos, true);
	pos += 4;
	if ( this.xfer_type === 2 /* Control */ ) {
		this.setup = raw_packet.slice(pos, pos + 8);
	}
	else if ( this.xfer_type === 0 /* ISO */ ) {
		this.iso = {
			error_count: raw_packet.readInt32LE(pos, true),
			numdesc: raw_packet.readInt32LE(pos + 4, true)
		}
	}
	pos += 8;
	this.interval = raw_packet.readInt32LE(pos, true);
	pos += 4;
	this.start_frame = raw_packet.readInt32LE(pos, true);
	pos += 4;
	this.xfer_flags = raw_packet.readUInt32LE(pos, true);
	pos += 4;
	this.ndesc = raw_packet.readUInt32LE(pos, true);
	pos += 4;

	if ( pos < raw_packet.length ) {
		this.leftover_data = raw_packet.slice(pos);
	}
	if ( this.emitter ) { this.emitter.emit("usb", this); }
	return this;
}

UsbPacket.prototype.decoderName = "usb-packet";
UsbPacket.prototype.eventsOnDecode = true;

UsbPacket.prototype.toString = function () {
	var ret = "";

	ret += "id 0x" + this.id.toNumber().toString(16) + " ";
	ret += "type " + this.type + " '" + String.fromCharCode(this.type) + "' ";
	ret += "xfer_type 0x" + this.xfer_type.toString(16) + " ";
	switch ( this.xfer_type ) {
		case 0:
			ret += "(ISO) ";
			break;
		case 1:
			ret += "(INTR) ";
			break;
		case 2:
			ret += "(CTRL) ";
			break;
		case 3:
			ret += "(BULK) ";
			break;
		default:
			ret += "(UNK) ";
			break;
	}
	ret += "epnum 0x" + this.epnum.toString(16);
	if ( this.epnum & 0x80 ) {
		ret += " (IN) ";
	}
	else {
		ret += " (OUT) ";
	}
	ret += "devnum " + this.devnum + " ";
	ret += "busnum " + this.busnum + " ";
	ret += "flag_setup " + this.flag_setup + " ";
	ret += "flag_data '" + String.fromCharCode(this.flag_data) + "' ";
	ret += "ts_sec " + this.ts_sec.toNumber() + " ";
	ret += "ts_usec " + this.ts_usec + " ";
	ret += "status " + this.status + " ";
	ret += "length " + this.length + " ";
	ret += "len_cap " + this.len_cap + " ";
	if ( this.xfer_type === 2 /* Control */ ) {
		ret += "setup " + this.setup.toString('hex') + " ";
	}
	else if ( this.xfer_type === 0 /* ISO */ ) {
		ret += "iso.error_count " + this.iso.error_count + " ";
		ret += "iso.numdesc " + this.iso.numdesc + " ";
	}
	ret += "interval " + this.interval + " ";
	ret += "start_frame " + this.start_frame + " ";
	ret += "xfer_flags 0x" + this.xfer_flags.toString(16) + " ";
	ret += "ndesc " + this.ndesc;
	if ( this.leftover_data ) {
		ret += " leftover_data " + this.leftover_data.toString('hex');
	}

	return ret;
};

module.exports =  UsbPacket;
