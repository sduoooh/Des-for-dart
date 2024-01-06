// Trans from des.js to dart, with some modification

// Accepts one parameter as your message
// And a non-zero number of arguments as your keys but it must within a list


class Des {
  String strEnc(String data, List<String> keys) {
    var dataLength = data.length;
    var keyLength = keys.length;
    if (dataLength * keyLength == 0) {
      throw new Exception("data or key is missing");
    }

    var encrypted = "";
    var dataBytes = data.codeUnits;
    var key = keys.map((e) => _getKeyBytes(e)).toList();
    var times = (dataLength / 4).ceil();
    for (var i = 0; i < times; i++) {
      var dataByte = _strToBt(dataBytes.sublist(4 * i).take(4));
      var temp = dataByte;
      for (var j = 0; j < keyLength; j++) {
        for (var k = 0; k < key[j].length; k++) {
          temp = _enc(temp, key[j][k]);
        }
      }
      encrypted = encrypted + _bt64ToHex(temp);
    }
    return encrypted;
  }

  List<List<int>> _getKeyBytes(String key) {
    if (key.isEmpty) {
      throw new Exception("any keys are missing");
    }

    List<List<int>> keyBytes = List.empty(growable: true);
    var times = (key.length / 4).ceil();

    for (var i = 0; i < times; i++) {
      keyBytes.add(_strToBt(key.codeUnits.sublist(4 * i).take(4)));
    }

    return keyBytes;
  }

  // 转换逻辑：
  // 计 A 为需要转换的母数，B 为当前二进制位的权重值（即 2 ^ * ）
  // A / B = C ，若 C 不为整数，则意味着当前位与以上位的权重的随机线性组合都无法完整表示 A
  // 若 C 为整数，其用 2 * n + 1 通项可表示时，意味着其可用 n 个上一位权重与 单个本位权重的组合完整表示该值，亦即本位为 1
  // 若用 2 * n 可表示时，意味着只需 n 个上一位权重即可完整表示该值，亦即本位为 0

  List<int> _strToBt(str) {
    if (str is String) {
      str = str.codeUnits;
    }
    var bytes = (List.of(str) + [0, 0, 0]).sublist(0, 4);
    final bt = List<int>.filled(64, 0);

    for (var i = 0; i < 4; i++) {
      for (var j = 15; j >= 0; j--) {
        var pow = 1 << j;

        bt[16 * i + 15 - j] = (bytes[i] / pow).floor() % 2;

        // 本位及以上位即可完全表示该字节
        if (bytes[i] % pow == 0) {
          break;
        }
      }
    }
    return bt;
  }

  List<int> _enc(List<int> dataByte, List<int> keyByte) {
    var keys = _generateKeys(keyByte);
    var ipByte = _initPermute(dataByte);
    var ipLeft = List.filled(32, 0);
    var ipRight = List.filled(32, 0);
    var tempLeft = List.filled(32, 0);
    for (var k = 0; k < 32; k++) {
      ipLeft[k] = ipByte[k];
      ipRight[k] = ipByte[32 + k];
    }
    for (var i = 0; i < 16; i++) {
      for (var j = 0; j < 32; j++) {
        tempLeft[j] = ipLeft[j];
        ipLeft[j] = ipRight[j];
      }
      var key = List.filled(48, 0);
      for (var m = 0; m < 48; m++) {
        key[m] = keys[i][m];
      }
      var tempRight = _xor(
          _pPermute(_sBoxPermute(_xor(_expandPermute(ipRight), key))), tempLeft);
      for (var n = 0; n < 32; n++) {
        ipRight[n] = tempRight[n];
      }
    }

    var finalData = List.filled(64, 0);
    for (var i = 0; i < 32; i++) {
      finalData[i] = ipRight[i];
      finalData[32 + i] = ipLeft[i];
    }
    return _finallyPermute(finalData);
  }

  String _bt64ToHex(List<int> byteData) {
    var hex = "";
    for (var i = 0; i < 16; i++) {
      var bt = byteData.sublist(i * 4, i * 4 + 4).join();
      hex += int.parse(bt, radix: 2).toRadixString(16);
    }
    return hex;
  }

  List<List<int>> _generateKeys(List<int> keyByte) {
    var key = List.filled(56, 0);
    List<List<int>> keys = List.generate(16, (index) => List.filled(48, 0));

    var loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    for (var i = 0; i < 7; i++) {
      for (var j = 0, k = 7; j < 8; j++, k--) {
        key[i * 8 + j] = keyByte[8 * k + i];
      }
    }

    for (var i = 0; i < 16; i++) {
      var tempLeft = 0;
      var tempRight = 0;
      for (var j = 0; j < loop[i]; j++) {
        tempLeft = key[0];
        tempRight = key[28];
        for (var k = 0; k < 27; k++) {
          key[k] = key[k + 1];
          key[28 + k] = key[29 + k];
        }
        key[27] = tempLeft;
        key[55] = tempRight;
      }
      var tempKey = List.filled(48, 0);
      tempKey[0] = key[13];
      tempKey[1] = key[16];
      tempKey[2] = key[10];
      tempKey[3] = key[23];
      tempKey[4] = key[0];
      tempKey[5] = key[4];
      tempKey[6] = key[2];
      tempKey[7] = key[27];
      tempKey[8] = key[14];
      tempKey[9] = key[5];
      tempKey[10] = key[20];
      tempKey[11] = key[9];
      tempKey[12] = key[22];
      tempKey[13] = key[18];
      tempKey[14] = key[11];
      tempKey[15] = key[3];
      tempKey[16] = key[25];
      tempKey[17] = key[7];
      tempKey[18] = key[15];
      tempKey[19] = key[6];
      tempKey[20] = key[26];
      tempKey[21] = key[19];
      tempKey[22] = key[12];
      tempKey[23] = key[1];
      tempKey[24] = key[40];
      tempKey[25] = key[51];
      tempKey[26] = key[30];
      tempKey[27] = key[36];
      tempKey[28] = key[46];
      tempKey[29] = key[54];
      tempKey[30] = key[29];
      tempKey[31] = key[39];
      tempKey[32] = key[50];
      tempKey[33] = key[44];
      tempKey[34] = key[32];
      tempKey[35] = key[47];
      tempKey[36] = key[43];
      tempKey[37] = key[48];
      tempKey[38] = key[38];
      tempKey[39] = key[55];
      tempKey[40] = key[33];
      tempKey[41] = key[52];
      tempKey[42] = key[45];
      tempKey[43] = key[41];
      tempKey[44] = key[49];
      tempKey[45] = key[35];
      tempKey[46] = key[28];
      tempKey[47] = key[31];

      for (var m = 0; m < 48; m++) {
        keys[i][m] = tempKey[m];
      }
    }
    return keys;
  }

  List<int> _initPermute(List<int> originalData) {
    var ipByte = List.filled(64, 0);
    for (var i = 0, m = 1, n = 0; i < 4; i++, m += 2, n += 2) {
      for (var j = 7, k = 0; j >= 0; j--, k++) {
        ipByte[i * 8 + k] = originalData[j * 8 + m];
        ipByte[i * 8 + k + 32] = originalData[j * 8 + n];
      }
    }
    return ipByte;
  }

  List<int> _expandPermute(rightData) {
    var epByte = List.filled(48, 0);
    for (var i = 0; i < 8; i++) {
      if (i == 0) {
        epByte[i * 6 + 0] = rightData[31];
      } else {
        epByte[i * 6 + 0] = rightData[i * 4 - 1];
      }
      epByte[i * 6 + 1] = rightData[i * 4 + 0];
      epByte[i * 6 + 2] = rightData[i * 4 + 1];
      epByte[i * 6 + 3] = rightData[i * 4 + 2];
      epByte[i * 6 + 4] = rightData[i * 4 + 3];
      if (i == 7) {
        epByte[i * 6 + 5] = rightData[0];
      } else {
        epByte[i * 6 + 5] = rightData[i * 4 + 4];
      }
    }
    return epByte;
  }

  List<int> _xor(List<int> byteOne, List<int> byteTwo) {
    var xorByte = List.filled(byteOne.length, 0);
    for (var i = 0; i < byteOne.length; i++) {
      xorByte[i] = byteOne[i] ^ byteTwo[i];
    }
    return xorByte;
  }

  List<int> _sBoxPermute(List<int> expandByte) {
    var sBoxByte = List.filled(32, 0);
    var binary = "";
    var s1 = [
      [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ];

    var s2 = [
      [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ];

    var s3 = [
      [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ];

    var s4 = [
      [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ];

    var s5 = [
      [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ];

    var s6 = [
      [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ];

    var s7 = [
      [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ];

    var s8 = [
      [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ];

    for (var m = 0; m < 8; m++) {
      var i = 0, j = 0;
      i = expandByte[m * 6 + 0] * 2 + expandByte[m * 6 + 5];
      j = expandByte[m * 6 + 1] * 2 * 2 * 2 +
          expandByte[m * 6 + 2] * 2 * 2 +
          expandByte[m * 6 + 3] * 2 +
          expandByte[m * 6 + 4];

      binary = [s1, s2, s3, s4, s5, s6, s7, s8][m][i][j]
          .toRadixString(2)
          .padLeft(4, '0');

      for (var i = 0; i < 4; i++) {
        sBoxByte[m * 4 + i] = int.parse(binary.substring(i, i + 1));
      }
    }
    return sBoxByte;
  }

  List<int> _pPermute(List<int> sBoxByte) {
    var pBoxPermute = List.filled(32, 0);
    pBoxPermute[0] = sBoxByte[15];
    pBoxPermute[1] = sBoxByte[6];
    pBoxPermute[2] = sBoxByte[19];
    pBoxPermute[3] = sBoxByte[20];
    pBoxPermute[4] = sBoxByte[28];
    pBoxPermute[5] = sBoxByte[11];
    pBoxPermute[6] = sBoxByte[27];
    pBoxPermute[7] = sBoxByte[16];
    pBoxPermute[8] = sBoxByte[0];
    pBoxPermute[9] = sBoxByte[14];
    pBoxPermute[10] = sBoxByte[22];
    pBoxPermute[11] = sBoxByte[25];
    pBoxPermute[12] = sBoxByte[4];
    pBoxPermute[13] = sBoxByte[17];
    pBoxPermute[14] = sBoxByte[30];
    pBoxPermute[15] = sBoxByte[9];
    pBoxPermute[16] = sBoxByte[1];
    pBoxPermute[17] = sBoxByte[7];
    pBoxPermute[18] = sBoxByte[23];
    pBoxPermute[19] = sBoxByte[13];
    pBoxPermute[20] = sBoxByte[31];
    pBoxPermute[21] = sBoxByte[26];
    pBoxPermute[22] = sBoxByte[2];
    pBoxPermute[23] = sBoxByte[8];
    pBoxPermute[24] = sBoxByte[18];
    pBoxPermute[25] = sBoxByte[12];
    pBoxPermute[26] = sBoxByte[29];
    pBoxPermute[27] = sBoxByte[5];
    pBoxPermute[28] = sBoxByte[21];
    pBoxPermute[29] = sBoxByte[10];
    pBoxPermute[30] = sBoxByte[3];
    pBoxPermute[31] = sBoxByte[24];
    return pBoxPermute;
  }

  List<int> _finallyPermute(List<int> endByte) {
    var fpByte = List.filled(64, 0);
    fpByte[0] = endByte[39];
    fpByte[1] = endByte[7];
    fpByte[2] = endByte[47];
    fpByte[3] = endByte[15];
    fpByte[4] = endByte[55];
    fpByte[5] = endByte[23];
    fpByte[6] = endByte[63];
    fpByte[7] = endByte[31];
    fpByte[8] = endByte[38];
    fpByte[9] = endByte[6];
    fpByte[10] = endByte[46];
    fpByte[11] = endByte[14];
    fpByte[12] = endByte[54];
    fpByte[13] = endByte[22];
    fpByte[14] = endByte[62];
    fpByte[15] = endByte[30];
    fpByte[16] = endByte[37];
    fpByte[17] = endByte[5];
    fpByte[18] = endByte[45];
    fpByte[19] = endByte[13];
    fpByte[20] = endByte[53];
    fpByte[21] = endByte[21];
    fpByte[22] = endByte[61];
    fpByte[23] = endByte[29];
    fpByte[24] = endByte[36];
    fpByte[25] = endByte[4];
    fpByte[26] = endByte[44];
    fpByte[27] = endByte[12];
    fpByte[28] = endByte[52];
    fpByte[29] = endByte[20];
    fpByte[30] = endByte[60];
    fpByte[31] = endByte[28];
    fpByte[32] = endByte[35];
    fpByte[33] = endByte[3];
    fpByte[34] = endByte[43];
    fpByte[35] = endByte[11];
    fpByte[36] = endByte[51];
    fpByte[37] = endByte[19];
    fpByte[38] = endByte[59];
    fpByte[39] = endByte[27];
    fpByte[40] = endByte[34];
    fpByte[41] = endByte[2];
    fpByte[42] = endByte[42];
    fpByte[43] = endByte[10];
    fpByte[44] = endByte[50];
    fpByte[45] = endByte[18];
    fpByte[46] = endByte[58];
    fpByte[47] = endByte[26];
    fpByte[48] = endByte[33];
    fpByte[49] = endByte[1];
    fpByte[50] = endByte[41];
    fpByte[51] = endByte[9];
    fpByte[52] = endByte[49];
    fpByte[53] = endByte[17];
    fpByte[54] = endByte[57];
    fpByte[55] = endByte[25];
    fpByte[56] = endByte[32];
    fpByte[57] = endByte[0];
    fpByte[58] = endByte[40];
    fpByte[59] = endByte[8];
    fpByte[60] = endByte[48];
    fpByte[61] = endByte[16];
    fpByte[62] = endByte[56];
    fpByte[63] = endByte[24];
    return fpByte;
  }
}
