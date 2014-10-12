f1 = open("/home/forecast/UDPforecast.txt","r")
file1 = f1.readlines()

result = file1[len(file1)-1][15] + file1[len(file1)-1][16]

if result > 7:
	os.system("python /home/src_sql_July_2013_Madhu/madhu/protect/packet_filter.py")
