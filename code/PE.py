# -*-coding:utf-8-*-
import sys
import struct


class PeParser:
    def __init__(self, file_path):
        self.MZSIG = b'MZ'
        self.PESIG = b'PE\0\0'
        self.path = file_path

    # 将十六进制数据转换为小端格式的数值
    def get_dword(self, data):
        return struct.unpack('<L', data)[0]

    # 提取ASCII字符串
    def get_string(self, ptr):
        beg = ptr
        while ptr < len(self.data) and self.data[ptr] != 0:
            ptr += 1
        return self.data[beg:ptr]

    def parse(self):
        self.read_data()
        if not self.is_valid_pe():
            print("[Error] Invalid PE file")
        self.parse_import_table()
        # 读取文件数据

    def read_data(self):
        fd = open(self.path, "rb")
        self.data = fd.read()
        fd.close()
        # 检查文件合法性并读取数据

    def is_valid_pe(self):
        dos_header_data = self.data[:2]
        if not dos_header_data == self.MZSIG:
            print("")
            return False
        self.dos_nt_rva = self.get_dword(self.data[60:64])
        dos_nt_signature = self.data[self.dos_nt_rva:self.dos_nt_rva + 4]
        self.numberofsections = struct.unpack('<h', self.data[self.dos_nt_rva + 6:self.dos_nt_rva + 8])[0]
        self.sizeofoptionheader = struct.unpack('<h', self.data[self.dos_nt_rva + 0x14:self.dos_nt_rva + 0x16])[
            0]  # header大小
        self.numberofRvaAndSizes = self.get_dword(self.data[self.dos_nt_rva + 0x74:self.dos_nt_rva + 0x78])
        self.sectionrva = self.dos_nt_rva + self.sizeofoptionheader + 0x18
        self.import_RVA = self.get_dword(self.data[self.dos_nt_rva + 0x80:self.dos_nt_rva + 0x84])
        self.import_Size = self.get_dword(self.data[self.dos_nt_rva + 0x84:self.dos_nt_rva + 0x88])
        self.solvesection()
        if not dos_nt_signature == self.PESIG:
            return False
        return True

    # RVA转偏移地址
    def rva_to_offset(self, rva):
        for i in range(self.numberofsections - 1):
            col1 = self.section[i]
            col2 = self.section[i + 1]
            if rva < col2[1] and rva > col1[1]:
                return rva - col1[1] + col1[3]

    def solvesection(self):
        self.section = []
        ptr = self.sectionrva
        # print(hex(ptr))
        for i in range(self.numberofsections):
            col = []
            col.append(self.data[ptr + 40 * i:ptr + 8 + 40 * i])
            col.append(self.get_dword(self.data[ptr + 12 + 40 * i:ptr + 16 + 40 * i]))  # rva
            col.append(self.get_dword(self.data[ptr + 16 + 40 * i:ptr + 20 + 40 * i]))  # 大小
            col.append(self.get_dword(self.data[ptr + 20 + 40 * i:ptr + 24 + 40 * i]))  # 区块偏移
            self.section.append(col)

    # 输入表结构解析
    def parse_import_table(self):
        print("\t输入表大小:" + str(hex(self.import_Size)))
        print("\t输入表RVA: " + hex(self.import_RVA))
        i = 0
        offect = self.rva_to_offset(self.import_RVA)
        ptr = self.data[offect:offect + 0x14 + 1]

        import_data = []

        while not ptr == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':

            i = i + 1
            col = []
            col.append(self.get_dword(ptr[0:4]))
            col.append(self.get_dword(ptr[4:8]))
            col.append(self.get_dword(ptr[8:12]))
            col.append(self.get_dword(ptr[12:16]))
            col.append(self.get_dword(ptr[16:20]))
            import_data.append(col)

            ptr = self.data[offect + 0x14 * i:offect + 0x14 * i + 0x14]
        for j in range(i):
            col = import_data[j]

            print("\t调用的dll名称为：")
            print("\t " + self.get_string(self.rva_to_offset(col[3])).decode('utf-8'))
            print('\t------------------------------')
            print("\t相应的调用函数名称为:")
            self.parse_iid_int(self.rva_to_offset(col[0]))
            print('')

    # 解析每个IID对应的IMAGE_THUNK_DATA类型的INT数组
    def parse_iid_int(self, ptr):
        i = 0

        Drva = self.get_dword(self.data[ptr:ptr + 4])


        while not Drva == 0:
            i = i + 1
            rva = int(self.rva_to_offset(Drva))
            print("\t " + self.get_string(rva+2).decode('utf-8'))
            Drva = self.get_dword(self.data[ptr + i * 4:ptr + 4 * i + 4])


if __name__ == "__main__":
    if len(sys.argv) == 2:
        p = PeParser(sys.argv[1])
        p.parse()
