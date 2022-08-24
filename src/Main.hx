import sys.FileSystem;
import sys.io.FileInput;
import haxe.io.Bytes;
import sys.io.FileSeek;
import sys.io.File;

final DOS_MAGIC = 0x5a4d;
final PE_MAGIC = 0x4550;
final PE32PLUS_MAGIC = 0x20b;
final CHECKSUM_OFFSET = 0x160;

class Main {
	static public function main() {
		var args = Sys.args();
		var env = Sys.environment();

		if (env["HAXELIB_RUN"] == "1") {
			args.pop();
		}

		if (args.length != 2) {
			usage("");
		}

		final subsystem = switch (args[0].toLowerCase()) {
			case "windows": 2;
			case "console": 3;
			default:
				usage('Invalid subsystem: ${args[0]}');
				return;
		};

		final fp = args[1];
		var contents = File.getBytes(fp);
		var subsystemOffset = getSubsystemOffset(contents);
		if (subsystemOffset == -1) {
			Sys.println('Not a patchable PE file: $fp');
			Sys.exit(2);
		}

		// Set the subsystem to the argument provided.
		contents.setUInt16(subsystemOffset, subsystem);

		var checksum = calculateChecksum(contents);
		contents.setInt32(CHECKSUM_OFFSET, checksum);
		File.saveBytes(fp, contents);
	}

	static function usage(msg:String) {
		if (msg.length > 0) {
			Sys.println('$msg\n');
		}
		Sys.println("Usage:\n  haxelib run chsub [windows|console] EXE_FILE");
		Sys.exit(1);
	}

	static function getSubsystemOffset(f:Bytes):Int {
		// More information available at the microsoft's official reference:
		// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
		if (f.getUInt16(0) != DOS_MAGIC) {
			return -1;
		}
		final peHeaderOffset = f.getInt32(0x3c);
		if (f.getUInt16(peHeaderOffset) != PE_MAGIC) {
			return -1;
		}
		// Check optional header size, not a PE image if zero.
		if (f.getUInt16(peHeaderOffset + 20) == 0) {
			return -1;
		}
		// Optional header immediately follows the 24 byte PE header.
		final optionalHeaderOffset = peHeaderOffset + 24;
		// Check that this is a PE32+ image.
		if (f.getUInt16(optionalHeaderOffset) != PE32PLUS_MAGIC) {
			return -1;
		}
		// Then the subsystem is 68 bytes into the optional header.
		return optionalHeaderOffset + 68;
	}

	static function calculateChecksum(f:Bytes):Int {
		// This is slightly modified from the C implementation provided in
		// Section 4.1 of RFC 1071: https://www.rfc-editor.org/rfc/rfc1071#section-4.1
		// A deeper dive can be found at:
		// https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm
		var pos = 0;
		var sum = 0;
		while (pos < f.length) {
			// Skip the checksum in the file.
			if (pos == CHECKSUM_OFFSET) {
				pos += 4;
			} else {
				sum += f.getUInt16(pos);
				pos += 2;
			}
		}

		sum = (sum & 0xFFFF) + (sum >> 16);
		sum += (sum >> 16);
		sum &= 0xFFFF;
		return sum + f.length;
	}
}
