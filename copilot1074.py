# 1074. Number of Submatrices That Sum to Target

'''
Given a matrix and a target, return the number of non-empty submatrices that sum to target.

A submatrix x1, y1, x2, y2 is the set of all cells matrix[x][y] with x1 <= x <= x2 and y1 <= y <= y2.

Two submatrices (x1, y1, x2, y2) and (x1', y1', x2', y2') are different if they have some coordinate that is different: for example, if x1 != x1'.
'''

class Solution(object):
    def numSubmatrixSumTarget(self, matrix, target):
        """
        :type matrix: List[List[int]]
        :type target: int
        :rtype: int
        """
        m = len(matrix)
        n = len(matrix[0])
        res = 0
        for i in range(m):
            for j in range(1, n):
                matrix[i][j] += matrix[i][j-1]
        for i in range(n):
            for j in range(i, n):
                d = {0:1}
                cur = 0
                for k in range(m):
                    cur += matrix[k][j] - (matrix[k][i-1] if i > 0 else 0)
                    res += d.get(cur - target, 0)
                    d[cur] = d.get(cur, 0) + 1
        return res