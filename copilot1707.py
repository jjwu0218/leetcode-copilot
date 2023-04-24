# 1707. Maximum XOR With an Element From Array

'''
You are given an array nums consisting of non-negative integers. You are also given a queries array, where queries[i] = [xi, mi].

The answer to the ith query is the maximum bitwise XOR value of xi and any element of nums that does not exceed mi. In other words, the answer is max(nums[j] XOR xi) for all j such that nums[j] <= mi. If all elements in nums are larger than mi, then the answer is -1.

Return an integer array answer where answer.length == queries.length and answer[i] is the answer to the ith query.
'''

class Solution(object):
    def maximizeXor(self, nums, queries):
        """
        :type nums: List[int]
        :type queries: List[List[int]]
        :rtype: List[int]
        """
        nums.sort()
        queries = sorted(enumerate(queries), key=lambda x: x[1][1])
        res = [-1] * len(queries)
        trie = {}
        j = 0
        for i, (x, m) in queries:
            while j < len(nums) and nums[j] <= m:
                self.insert(trie, nums[j])
                j += 1
            if trie:
                res[i] = self.search(trie, x)
        return res