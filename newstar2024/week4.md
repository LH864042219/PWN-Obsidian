# NS24_Week4_CrazyCat_20233001236_刘涵

## 信息
- 平台ID：CrazyCat
- 姓名：刘涵
- 学号：20233001236
- 轮次：Week4

# 解出题目
![[Pasted image 20241022151055.png]]

# PWN
## Maze_Rust
![[Pasted image 20241022151223.png]]
运行程序，发现输入1可以生成迷宫，输入3是查看迷宫
![[Pasted image 20241022151340.png]]
输入wasd可以移动
![[Pasted image 20241022151406.png]]
那么这一部分可以编程解决，让其将迷宫走出。
输入2，他会要求我们输入一个神秘代码
![[Pasted image 20241022151452.png]]
根据我的常识和提示，神秘数字必定是0721
![[Pasted image 20241022151528.png]]
事实证明确实如此。很抱歉没能在别的地方找到这个神秘数字该怎么正常获得不过 orz
exp:
```python
from pwn import *

def parse_maze(maze):
    return [list(row.decode()) for row in maze]

def find_start_and_goal(maze):
    start = None
    goal = None
    for i, row in enumerate(maze):
        for j, cell in enumerate(row):
            if cell == 'P':
                start = (i, j)
            elif cell == 'G':
                goal = (i, j)
    return start, goal

def is_valid_move(maze, x, y, visited):
    return 0 <= x < len(maze) and 0 <= y < len(maze[0]) and maze[x][y] != '#' and (x, y) not in visited

def dfs(maze, x, y, goal, path, visited):
    if (x, y) == goal:
        return True
    visited.add((x, y))
    directions = [(-1, 0, 'w'), (1, 0, 's'), (0, -1, 'a'), (0, 1, 'd')]
    for dx, dy, direction in directions:
        nx, ny = x + dx, y + dy
        if is_valid_move(maze, nx, ny, visited):
            path.append((nx, ny, direction))
            if dfs(maze, nx, ny, goal, path, visited):
                return True
            path.pop()
    return False

def solve_maze(maze):
    maze = parse_maze(maze)
    start, goal = find_start_and_goal(maze)
    if not start or not goal:
        return None
    path = [(start[0], start[1], '')]
    visited = set()
    if dfs(maze, start[0], start[1], goal, path, visited):
        return path
    return None

def path_to_directions(path):
    directions = [step[2] for step in path if step[2]]
    return ''.join(directions)

def print_maze_with_path(maze, path):
    maze = parse_maze(maze)
    for x, y, _ in path:
        if maze[x][y] not in ('P', 'G'):
            maze[x][y] = '.'
    for row in maze:
        print(''.join(row))

context(os='linux', arch='amd64', log_level='DEBUG')
local = False
if local:
    p = process('./Maze_Rust')
else:
    p = remote('8.147.129.74', 36911)
p.recvuntil(b'Handle The Maze\n')
p.sendline(b'0721')
p.recvuntil(b'Handle The Maze\n')
p.sendline(b'1')
p.recvuntil(b'Handle The Maze\n')
p.sendline(b'3')
maze = p.recvuntil(b'You can').split(b'\n')[:-1]

path = solve_maze(maze)
if path:
    print_maze_with_path(maze, path)
    directions = path_to_directions(path)
    print("Directions:", directions)
else:
    print("No path found")

p.recvuntil(b'Pls input your path: ')
for i in directions[:-1]:
    p.sendline(i.encode())
    p.recvuntil(b'Handle The Maze\n')
    p.sendline(b'3')
    p.recvuntil(b'Pls input your path: ')
p.sendline(directions[-1].encode())

p.interactive()
```
![[Pasted image 20241022152010.png]]
走迷宫的算法我直接让copilot代为生成，实际采用广搜或深搜都可以，找到一条路然后将路径转为wasd保留即可。