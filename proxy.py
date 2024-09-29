import requests
import bs4

print("x.com/gudetama_bf\n")
URL = 'https://free-proxy-list.net/?bjor=ka'
response = requests.get(URL)
soup = bs4.BeautifulSoup(response.text,"html.parser")
row = soup.body
f=open("proxy.1st", "a+")
for row in soup.findAll('table')[0].tbody.findAll('tr'):
    first_column = row.findAll('td')[0].contents
    third_column = row.findAll('td')[1].contents
    str = first_column + third_column
    str1 = (':'.join(str))
    print(str1)
    f.write("%s\n" % (str1))

f.write('\nEOF')
f.close()
