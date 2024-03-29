# 1944. Number of Visible People in a Queue

'''
There are n people standing in a queue, and they numbered from 0 to n - 1 in left to right order. You are given an array heights of distinct integers where heights[i] represents the height of the ith person.

A person can see another person to their right in the queue if everybody in between is shorter than both of them. More formally, the ith person can see the jth person if i < j and min(heights[i], heights[j]) > max(heights[i+1], heights[i+2], ..., heights[j-1]).

Return an array answer of length n where answer[i] is the number of people the ith person can see to their right in the queue.
'''

class Solution(object):
    def canSeePersonsCount(self, heights):
        """
        :type heights: List[int]
        :rtype: List[int]
        """
        n = len(heights)
        ans = [0] * n
        stack = []
        for i in range(n - 1, -1, -1):
            while stack and heights[i] > heights[stack[-1]]:
                ans[i] += 1 + ans[stack.pop()]
            if stack:
                ans[i] += 1
            stack.append(i)
        return ans