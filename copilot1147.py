# 1147. Longest Chunked Palindrome Decomposition

'''
You are given a string text. You should split it to k substrings (subtext1, subtext2, ..., subtextk) such that:

subtexti is a non-empty string.
The concatenation of all the substrings is equal to text (i.e., subtext1 + subtext2 + ... + subtextk == text).
subtexti == subtextk - i + 1 for all valid values of i (i.e., 1 <= i <= k).
Return the largest possible value of k.
'''

class Solution(object):
    def longestDecomposition(self, text):
        """
        :type text: str
        :rtype: int
        """
        n = len(text)
        if n == 0:
            return 0
        if n == 1:
            return 1
        for i in range(1, n//2+1):
            if text[:i] == text[n-i:]:
                return 2 + self.longestDecomposition(text[i:n-i])
        return 1