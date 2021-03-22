import sys

bits = []

total = 0
for l in open(sys.argv[1]):
	if not l.strip():
		continue
	d = l.strip().replace(" ", "")
	bits.append(d)

result = bytearray(16 * 128 * 2)

for i in range(16 * 128):
	v = 0
	row = i // 16
	col = i % 16
	col ^= 15
	for b in range(14):
		v |= (bits[row][col + b * 16] == "1") << (13 - b)

	result[i * 2] = v & 0xFF
	result[i * 2 + 1] = v >> 8

open(sys.argv[2], "wb").write(result)
