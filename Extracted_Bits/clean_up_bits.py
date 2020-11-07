import sys
import numpy as np

if len(sys.argv) != 3:
    print("Usage: %s [bit_file_to_fix] [bit_output_file]\n")
    exit()

file = open(sys.argv[1], 'r')
Lines = file.readlines()

new_file = open(sys.argv[2], 'w')

# Remove every 17th bit starting from 16th index
for line in Lines:
    line = line.strip()
    lister = list(line)
    x = np.array(lister)
    x = np.delete(x, np.arange(16, x.size, 17))
    x = ''.join(x.tolist())
    new_file.write(x + '\n')
