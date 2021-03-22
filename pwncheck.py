# coding=utf-8
import sys
import time
import string
import random
import os
import re
import paramiko
import lief
import socket
import operator
from zio import *
from struct import unpack


class Checker(object):
    def check_connect(ip, port, timeout1):
        try:
            io = zio((ip, port), timeout=timeout1)
            data = io.read_until(b"isn't it?")
            io.close()
            return True
        except:
            return False

    def check_base_function(ip, port, timeout1):
        try:
            io = zio((ip, port), timeout=timeout1)
            io.read_until(b'Input your choice:')
            io.write(b'c')  # function [c]create a book
            io.read_until(b'Which book do you want to create?')
            io.writeline(b'0')
            io.read_until(b'Input your choice:')
            io.write(b'e')  # fuction [e]edit book name
            io.read_until(b'Which book do you want to write?')
            io.writeline(b'0')
            io.read_until(b'You can input your book name:')
            io.writeline(b'0')
            io.read_until(b'Input your choice:')
            io.write(b't')  # fuction  [t]edit book content
            io.read_until(b'Which book do you want to write?')
            io.writeline(b'0')
            io.read_until(b'Now you can input your book content:')
            io.writeline(b'0')
            io.read_until(b'Input your choice:')
            io.write(b'd')  # fuction [d]delete
            io.read_until(b'Which book do you want to delete?')
            io.writeline(b'0')
            return True
        except:
            return False

    def check_create_amount(ip, port, timeout1):
        try:
            io = zio((ip, port), timeout=timeout1)
            for i in range(9):
                io.read_until(b'Input your choice:')
                io.write(b'c')  # function [c]create a book
                io.read_until(b'Which book do you want to create?')
                io.writeline(str(i))
                io.read_until(b'Done!')
            return True
        except:
            return False

    # can't change book name length

    def check_edit_length(ip, port, timeout1):
        try:
            io = zio((ip, port), timeout=timeout1)
            io.read_until(b'Input your choice:')
            io.write(b'c')  # function [c]create a book
            io.read_until(b'Which book do you want to create?')
            io.writeline(b'8')
            io.read_until(b'Input your choice:')
            io.write(b'e')  # fuction [e]edit book name
            io.read_until(b'Which book do you want to write?')
            io.writeline(b'8')
            io.read_until(b'You can input your book name:')
            test_name = ''.join(random.choice(
                string.ascii_letters + string.digits) for i in range(8))
            io.write(test_name)
            io.read_until(b'Input your choice:')
            io.write(b't')  # fuction  [t]edit book content
            io.read_until(b'Which book do you want to write?')
            io.writeline(b'8')
            test_content = ''.join(random.choice(
                string.ascii_letters + string.digits) for i in range(0x20))
            io.read_until(b'Now you can input your book content:')
            io.write(test_content)
            io.read_until(b'Input your choice:')
            io.writeline(b's')  # fuction  [t]edit book content
            return True
        except:
            return False

    def down_from_remote(host, remotepath, localpath, port=22):
        keyfile = open('./awd_rsa', 'r')
        private_key = paramiko.RSAKey.from_private_key(keyfile)
        t = paramiko.Transport((host, port))
        t.connect(username='root', pkey=private_key)
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.get(remotepath, localpath)

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

    def check_free(check_elf, ordinary_elf, call_free_address, size=5):
        # check call free change
        check_free_data = check_elf.get_content_from_virtual_address(
            call_free_address, size)
        ordinary_data = ordinary_elf.get_content_from_virtual_address(
            call_free_address, size)

        # equal => no change
        if operator.eq(check_free_data, ordinary_data):
            return True

        # if has 90 => nop free
        if 0x90 in check_free_data:
            return False
        # temporary
        return True

    def check_free_from_remote(host, pwnport, local, port=22):
        keyfile = open('./awd_rsa', 'r')
        private_key = paramiko.RSAKey.from_private_key(keyfile)
        # connect to host
        io = zio((host, pwnport))

        # get pid infomation
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        s.connect(hostname=host, port=port,
                  username='root', pkey=private_key)  #
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
        # malloc may be nopped
        if heap_info == '':
            io.close()
            return False

        # heap addr
        heap_addr_start, heap_addr_end = [int(i, 16) for i in re.match(
            "\w*-\w*", heap_info).group(0).split('-')]
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
        stdin, stdout, stderr = s.exec_command(
            "lsof -i:8888")
        with sftp.file("/proc/{0}/mem".format(checker_pwn_pid), mode='rb') as file:
            file.seek(heap_addr_start+0x8)
            chuck_1_size = int(str(unpack("<Q", file.read(8))[0]), 10)
            chuck_1_fd = int(str(unpack("<Q", file.read(8))[0]), 10)
            if (chuck_1_fd == (heap_addr_start+0x70)) and (chuck_1_size == 0x71):
                io.close()
                return True
            else:
                io.close()
                return False

    def compare_size(check_path, ordinary_path):
        size1 = os.path.getsize(check_path)
        size2 = os.path.getsize(ordinary_path)
        if size1 == size2:
            return True  # equal
        else:
            return False

    def check(ctx):
        ip = ctx.option.get('host')
        port = ctx.option.get('port')
        timeout = ctx.option.get('timeout')
        # check pwn function

        remotepath = '/pwn/pwn'
        localip = '192.168.244.1'
        check_path = './checkpwn'
        ordinary_path = './ordinarypwn'

        # get file
        try:
            down_from_remote(ip, remotepath, check_path)
        except:
            return ctx.result.failure(message='get file error')

        check_elf = lief.parse(check_path)
        ordinary_elf = lief.parse(ordinary_path)

        if not compare_size(check_path, ordinary_path):
            return ctx.result.failure(message='size check fail')

        # check free

        if not check_connect(ip, port, timeout):
            return ctx.result.failure(message='connect fail')

        if not check_free(check_elf, ordinary_elf, 0x400B62):
            return ctx.result.failure(message='free may nopped check fail')
        if not check_free_from_remote(ip, port, localip):
            return ctx.result.failure(message='free may nopped check fail')

        # check got & plt
        if not check_got(check_elf, ordinary_elf):
            return ctx.result.failure(message='got check fail')
        if not check_plt(check_elf, ordinary_elf):
            return ctx.result.failure(message='plt check fail')

        if not check_base_function(ip, port, timeout):
            return ctx.result.failure(message='base function check fail')

        if not check_create_amount(ip, port, timeout):
            return ctx.result.failure(message='create function check fail')

        if not check_edit_length(ip, port, timeout):
            return ctx.result.failure(message='edit function check fail')

        return ctx.result.success()


class Context(object):
    def __init__(self, option):
        self.option = option
        self.result = INFO


class INFO(object):
    def success(message=''):
        return {
            'status': 'success',
            'message': message
        }

    def failure(message=''):
        return {
            'status': 'failure',
            'message': message,
        }

    def debug(message=''):
        return {
            'status': 'debug',
            'message': message
        }
