from fuzzycontroller import *

newlist={}
Decision=Calculation()
newlist=Decision.MAC()
#newlist=Decision.FuzzyControl()
print 'SQL Method:'
method=newlist['SQL']
print method
