top_lines = []
N = 30

with open('threat_log.txt', 'r') as f:
    for i in range(N):
        try:
            line = next(f)
            top_lines.append(line)
        except StopIteration:
            break

for each in top_lines:
    print(each[-1] == '\n')
