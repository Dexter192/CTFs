import json
import sys

f = open('grid.json')
grid = json.load(f)

#print(grid)

"""
grid = [ [2, 2, 3],
        [4, 8, 2],
        [1, 5, 3] ]
"""
n = len(grid)
# With dynamic programming we should be able to get a runtime of O(n^2)
costs = [[None]*n]*n
costs = [[None for x in range(n)] for y in range(n)]
def path(x, y):
    if x > 0 and costs[x-1][y] == None:
        path(x-1, y)
    if y > 0 and costs[x][y-1] == None:
        path(x, y-1)
    if x == 0 and y == 0:
        costs[0][0] = grid[0][0]
        return

    cost_x = float("inf") if x == 0 else costs[x - 1][y] + grid[x][y]
    cost_y = float("inf") if y == 0 else costs[x][y - 1] + grid[x][y]
    costs[x][y] = min(cost_x, cost_y)
    return costs[x][y]

"""
O(n^n)
def closest_path(cost, x, y):
    #print(x,y)
    if x == n and y == n:
        return cost + grid[n][n]
    if (x > n or y > n):
        return sys.maxsize
    cost_x = closest_path(cost + grid[x][y], x, y + 1)
    cost_y = closest_path(cost + grid[x][y], x + 1, y)
    return min(cost_x, cost_y)
#p = closest_path(0, 0, 0)
"""
from Cryptodome.Util.number import long_to_bytes
p = path(n-1,n-1)
#p = costs[-1][-1] + grid[0][0]
print(p)
print(long_to_bytes(p))
# b'flag{dyn4m1c_pr0gramm1ng_pr0!}'
