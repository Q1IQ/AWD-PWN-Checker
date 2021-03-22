import os
import re
import paramiko
import lief
import operator
from zio import *
from struct import unpack


def down_from_remote(host, remotepath, localpath, port=22):
    keyfile = open('./awd_rsa', 'r')
    private_key = paramiko.RSAKey.from_private_key(keyfile)
    t = paramiko.Transport((host, port))
    t.connect(username='root', pkey=private_key)
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.get(remotepath, localpath)


def check_free_from_remote(host, local='192.168.244.1', port=22, pwnport=8888):
    keyfile = open('./awd_rsa', 'r')
    private_key = paramiko.RSAKey.from_private_key(keyfile)
    # connect to host
    io = zio((host, pwnport))

    # get pid infomation
    s = paramiko.SSHClient()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    s.connect(hostname=host, port=port, username='root', pkey=private_key)  #
    stdin, stdout, stderr = s.exec_command(
        "lsof -i:8888|grep "+local+"|grep  -v 'timeout' |awk '{print $2}'|head -n 1")
    checker_pwn_pid = stdout.read().decode().strip()

    # initialize heap
    io.read_until(b'Input your choice:')
    io.write('c')  # function [c]create a book
    io.read_until(b'Which book do you want to create?')
    io.writeline('0')
    io.read_until(b'Input your choice:')
    io.write('c')  # function [c]create a book
    io.read_until(b'Which book do you want to create?')
    io.writeline('1')
    # heap info
    stdin, stdout, stderr = s.exec_command(
        "cat /proc/{0}/maps".format(checker_pwn_pid))
    map_info = stdout.read().decode().split('\n')
    heap_info = ''
    if '[heap]' in map_info[3]:
        heap_info = map_info[3]
    else:
        for i in map_info:
            if '[heap]' in i:
                heap_info = i
                print('123123')
    # malloc may be nopped
    if heap_info == '':
        return False

    # heap addr
    heap_addr_start, heap_addr_end = [int(i, 16) for i in re.match(
        "\w*-\w*", heap_info).group(0).split('-')]
    print(heap_addr_start, heap_addr_end)
    print(heap_info)
    # check mem
    sftp = s.open_sftp()
    io.read_until(b'Input your choice:')
    io.write('d')  # fuction [d]delete
    io.read_until(b'Which book do you want to delete?')
    io.writeline('1')
    io.read_until(b'Input your choice:')
    io.write('d')  # fuction [d]delete
    io.read_until(b'Which book do you want to delete?')
    io.writeline('0')
    # if free is there, heap should be bin->0->1
    with sftp.file("/proc/{0}/mem".format(checker_pwn_pid), mode='rb') as file:
        file.seek(heap_addr_start+0x8)
        chuck_1_size = int(str(unpack("<Q", file.read(8))[0]), 10)
        chuck_1_fd = int(str(unpack("<Q", file.read(8))[0]), 10)
        if (chuck_1_fd == (heap_addr_start+0x70)) and (chuck_1_size == 0x71):
            return True
        else:
            return False


def compare_data(check_elf, ordinary_elf, address, size):
    check_data = check_elf.get_content_from_virtual_address(address, size)
    ordinary_data = ordinary_elf.get_content_from_virtual_address(
        address, size)
    if operator.eq(check_data, ordinary_data):
        return True  # equal
    else:
        return False


def check_got(check_elf, ordinary_elf):
    section = check_elf.get_section('.got.plt')
    got_address = section.virtual_address
    if(compare_data(check_elf, ordinary_elf, got_address, section.size)):
        return True
    else:
        return False


def check_plt(check_elf, ordinary_elf):
    section = check_elf.get_section('.plt')
    plt_address = section.virtual_address
    if(compare_data(check_elf, ordinary_elf, plt_address, section.size)):
        return True
    else:
        return False


def hexprint(a): return print([hex(i) for i in a])


def check_free(check_elf, ordinary_elf, call_free_address, size=5):
    # check call free change
    check_free_data = check_elf.get_content_from_virtual_address(
        call_free_address, size)
    ordinary_data = ordinary_elf.get_content_from_virtual_address(
        call_free_address, size)

    check_free_data = [0x90, 169, 251, 255, 255]
    hexprint(check_free_data)
    # equal => no change
    if operator.eq(check_free_data, ordinary_data):
        return True

    # if has 90 =>nop free
    if 0x90 in check_free_data:
        return False

    # print([str(i) for i in check_elf.imported_symbols])
    # print([str(i) for i in check_elf.dynamic_entries])
    # print([str(i) for i in check_elf.dynamic_relocations])
    #print([str(i) for i in check_elf.dynamic_symbols])
    # xref
    #print([str(i) for i in check_elf.pltgot_relocations])
    # print(check_elf.get_relocation('free'))
    # free_address=check_elf.get_relocation('free').address
    # print([hex(i) for i in check_elf.xref(free_address)])

    pass


def compare_size(check_path, ordinary_path):
    size1 = os.path.getsize(check_path)
    size2 = os.path.getsize(ordinary_path)
    if size1 == size2:
        return True  # equal
    else:
        return False


check_free_from_remote('192.168.244.147')

# text:0000000000400B62 E8 A9 FB FF FF             call free
check_free(check_elf, ordinary_elf, 0x400B62)
