#!/usr/bin/python

num_list = list(map(int, input().split()))
result_tries = list(list())
for num in num_list:
	result_tries.append([num])

print(result_tries)