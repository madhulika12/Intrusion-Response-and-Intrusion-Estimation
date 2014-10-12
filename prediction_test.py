import numpy as np
import statsmodels.api as sm

# get data
nsample = 100
x = np.linspace(0,10, 100)
X = sm.add_constant(np.column_stack((x, x**2)))
beta = np.array([1, 0.1, 10])
y = np.dot(X, beta) + np.random.normal(size=nsample)

# run the regression
results = sm.OLS(y, X).fit()

# look at the results
print results.summary()
