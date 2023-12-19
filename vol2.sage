
from random import SystemRandom
import binascii


W_RANGE = 10
Q_RANGE = 10

banner = '''-----------------------------------------------
    Merkle-HellmanCryptoTool vol.2
-----------------------------------------------'''




info = ("\nПрограммная реализация алгоритма шифрования на основе рюкзака (ранца), \nтакже известного как Алгоритм Меркла-Хеллмана"
		"\nДанная реализация предлагает возможности шифрования и дешифрования посредством данного алгоритма и взлом его на основе решетки"
		"\n\nРеализация: Евглевский В., Володин И., Демиденко А., Каденец А., Тихонова М."
		"\nгр.19-К-КБ1\n\n") 


		
info1 = "Так как в классическом виде ранцевая система Меркла-Хеллмана в вариации со сверхвозрастающим рюкзаком является уязвимой, \nто целесобразно модернизировать используемую в качестве закрытого ключа \nсверхвозрастающую последовательность таким образом, чтобы сверхвозрастающий рюкзак перестал таковым являться \n\n\nДанная программа является второй частью комплекса утилит для работы с ранцевой криптосистемой Меркла-Хеллмана. \n\nПЕРЕХОДИТЕ К ИСПОЛЬЗОВАНИЮ ДАННОЙ УТИЛИТЫ ТОЛЬКО ПОСЛЕ ИЗУЧЕНИЯ Merkle-HellmanCryptoTool vol.1!!! \n\n В данном решении предоставляются как возможности шифрования и дешифрования, так криптоанализа с использованием \nлишь открытого ключа и шифротекста. Имея эти данные за полиноминаьное время программа может раскрыть оригинальный текст исходного \nсообщения, используя алгоритм LLL. Для вывода справки по алгоритму нажмите цифру 4\n\n\n"


# Encryption related functions - start

# Verify if public key has a valid length
# (NOTE: in this implementation key-size is always equal to plaintext length in bits)
def verify_publickey(pt,public_key):
	return len("".join(format(ord(c),'b') for c in pt).rjust(len(pt)*8,"0")) == len(public_key)

def encrypt(pt,public_key):
	return str(sum([(int(bin(int(binascii.hexlify(pt.encode()),16))[2:].rjust(len(pt)*8,"0")[i])*public_key[i]) for i in range(0,len(public_key))]))

# (NOTE: in this implementation public key is not permutated)
def gen_keypair(pt_len):
	# Generating Private Key:
	# Generating random superincreasing set w
	w = []
	s = 2
	for _ in range(0,pt_len):
		value = SystemRandom().randrange(s,s+W_RANGE)
		w.append(value)
		s += value
	# Generating q such that q > sum
	q = SystemRandom().randrange(s,s+Q_RANGE)
	# Generating r such that r and q are coprime
	while True:
		r = SystemRandom().randrange(2,q)
		if egcd(r,q)[0] == 1:
			break
	private_key = (w,q,r)
	#Calculating Public Key:
	public_key = [(n*r)%q for n in w]
	return (public_key, private_key)

# Encryption related functions - end


# Auxiliary functions for gcd and modulo inverse calculations

def egcd(a,b):
	if a == 0:
		return (b,0,1)
	g,y,x = egcd(b%a,a)
	return (g,x-(b//a)*y,y)

def modinverse(a,m):
	g,x,y = egcd(a,m)
	if g != 1:
		raise Exception('Что-то пошло не так, модульной инверсии не существует')
	return x%m


# Decryption related functions - start

def verify_privatekey(private_key):
	if egcd(private_key[1],private_key[2])[0] != 1:
		print ("\nError: q and r are not coprime!\n")
		return False
	sum = 0
	for i in range(0,len(private_key[0])):
		if private_key[0][i] <= sum:
			print (private_key[0])
			print ("\nОшибка: w не является увеличивающейся последовательностью!\n")
			return False
		sum += private_key[0][i]
	if sum >= private_key[1]:
		print ("\nОшибка: q не больше суммы всех элементов w!\n")
		return False
	return True

def decrypt(ct,private_key):
	s = (ct*modinverse(private_key[2],private_key[1]))%private_key[1]
	pt = ""
	for i in range(len(private_key[0])-1,-1,-1):
		if private_key[0][i] <= s:
			s -= private_key[0][i]
			pt += "1"
		else:
			pt += "0"
	return binascii.unhexlify(hex((int(pt[::-1],2)))[2:].encode()).decode()

# Auxiliary functions for vector operations

def vsum(u,v):
	try:
		ret = []
		for i in range(0,len(v)):
			ret.append(v[i]+u[i])
		return ret
	except:
		print ("\nОшибка в вычислении векторной суммы!\n")

def scalar_product(n,v):
	try:
		ret = []
		for i in range(0,len(v)):
			ret.append(n*v[i])
		return ret
	except:
		print ("\nОшибка в вычислении векторного скалярного произведения!\n")

def dot_product(u,v):
	try:
		ret = 0
		for i in range(0,len(v)):
			ret += v[i]*u[i]
		return ret
	except:
		print ("\nОшибка в вычислении векторного точечного произведения!\n")

# Cryptanalysis related functions

def GramSchmidt(M):
	try:
		orthG = [M[0]]
		projection_coefficients = {}
		for j in range(1,len(M)):
			orthG.append(M[j])
			for i in range(0,j):
				projection_coefficients[str(i)+str(j)] = (dot_product(orthG[i],M[j]))/(dot_product(orthG[i],orthG[i]))
				orthG[j] = vsum(orthG[j],scalar_product(-1*projection_coefficients[str(i)+str(j)],orthG[i]))
		return (orthG,projection_coefficients)
	except:
		print ("\nОшибка в процессе ортогонализации Грама-Шмидта!\n")

def LLL(M,d):
	try:
		while True:
			GSoG, GSpc = GramSchmidt(M)
			for j in range(1,len(M)):
				for i in range(j-1,-1,-1):
					if abs(GSpc[str(i)+str(j)]) > 1/2:
						M[j] = vsum(M[j],scalar_product(-1*round(GSpc[str(i)+str(j)]),M[i]))
			GSoG, GSpc = GramSchmidt(M)
			try:
				for j in range(0,len(M)-1):
					tmp0 = vsum(GSoG[j+1],scalar_product(GSpc[str(j)+str(j+1)],GSoG[j]))
					if dot_product(tmp0,tmp0) < d*(dot_product(GSoG[j],GSoG[j])):
						tmp1 = M[j]
						M[j] = M[j+1]
						M[j+1] = tmp1
						raise Exception()
				return M
			except:
				continue
	except:
		print ("\nОшибка в расчетах уменьшения LLL!\n")


def break_cipher(ct,public_key):
	try:
		#Converting the knapsack problem into a lattice problem
		#Initializing and setting up the matrix M
		M = [[1 if i==j else 0 for i in range(0,len(public_key))] for j in range(0,len(public_key))]
		for i in range(0,len(public_key)):
			M[i].append(public_key[i])
		M.append([0 for _ in range(0,len(public_key))])
		M[len(public_key)].append(-ct)
		#Find short vectors in the lattice spanned by the columns of M
		short_vectors = LLL(M,0.99)
		print ("\nНайдены короткие векторы > " + str(short_vectors))
		flag = 0
		for vector in short_vectors:
			try:
				cur = ""
				for n in vector:
					cur += str(n)
					if n != 1 and n != 0:
						raise Exception()
				print ("\nНайден возможный открытый текст > " + binascii.unhexlify(hex(int(cur[:-1],2))[2:].encode()).decode() + "\n" )
				flag = 1
			except:
				continue

		if not flag:
			print ("\nНе найдено возможных открытых текстов с использованием сокращения LLL!\n")

	except:
		print ("\nНе удалось взломать шифрование рюкзака Меркла-Хеллмана для получения желаемого зашифрованного текста!\n")

# Decryption related functions - end


# The Main Function handles user input, menu conditions and the retrieval of information from provided text files

def main():
	print (banner)
	print(info)
	print(info1)
	while True:
		try:
			print ("1) Зашифровать\n2) Дешифровать\n3) Сгенерировать пару ключей\n4) Об алгоритме взлома\n5) Выход")
			op = str(input("> "))
		except:
			print ("Ошибка ввода")

		# Main menu option 1
		if op == "1":
			try:
				pt = str(input("Открытый текст для шифрования > "))
				print ("Открытый ключ:\n1) Использовать свой собственный ключ\n2) Есть генерация файлов ключей")
				op1 = str(input("> "))
			except:
				print ("Ошибка ввода")
				continue

			# Encrypt menu option 1
			if op1 == "1":
				try:
					pub_file =  str(input("Введите имя вашего файла с открытым ключом (файл должен содержать по одному номеру в строке).\n> "))
					public_key = []
					with open(pub_file,"r") as f:
						for line in f:
							if int(line[:-1]) <= 0:
								raise Exception()
							public_key.append(int(line[:-1]))
				except:
					print ("Ошибка ввода")
					continue
				if not verify_publickey(pt,public_key):
					print("\nОшибка ввода\n")
					continue

			# Encrypt menu option 2
			elif op1 == "2":
				try:
					key = gen_keypair(len(pt)*8)
					print ("\nПара ключей, сгенерированная для шифрования вашего открытого текста:\n\nОткрытый ключ > " + str(key[0]) + "\n\nЗакрытый ключ(w,q,r) > " + str(key[1]))
					with open("publickey.txt","w") as pub:
						for n in key[0]:
							pub.write(str(n) + "\n")
					with open("privatekey.txt","w") as prv:
						prv.write("w:\n")
						for n in key[1][0]:
							prv.write(str(n) + "\n")
						prv.write("q:\n")
						prv.write(str(key[1][1]) + "\n")
						prv.write("r:\n")
						prv.write(str(key[1][2]) + "\n")
					public_key = key[0]
					print ("\nОткрытый и закрытый ключи были сохранены в 'publickey.txt' and 'privatekey.txt' соответственно.\n")
				except:
					print ("\nОшибка ввода\n")
			else:
				print ("\nОшибка ввода\n")
				continue
			ct = encrypt(pt,public_key)
			print ("\nЗашифрованный текст > " + ct + "\n") 


		# Main menu option 2
		elif op == "2":
			try:
				ct = int(input("Зашифрованный текст для расшифровки (в десятичном формате) > "))
			except:
				print ("\nОшибка ввода\n")
				continue
			print ("\nЗакрытый ключ:\n1) Используйте свой собственный ключ\n2) Взломать шифр (закрытый ключ не требуется)")
			op2 = str(input("> "))

			# Decrypt menu option 1
			if op2 == "1":
				try:
					prv_file = str(input("\nВведите имя файла закрытого ключа:\n> "))
					values = []
					with open(prv_file,"r") as prv:
						for line in prv:
							if "w:" in line or "q:" in line or "r:" in line:
								continue
							if int(line[:-1]) <= 0:
								raise Exception()
							values.append(int(line[:-1]))
					w = values[:-2]
					q = values[-2:-1][0]
					r = values[-1:][0]
					private_key = (w,q,r)
					if not verify_privatekey(private_key):
						print ("\nНеверный ключ!\n")
						continue
					pt = decrypt(ct,private_key)
					print ("\nОткрытый текст > " + pt + "\n")
				except:
					print ("\nНеверный ключ!\n")
					continue


			# Decrypt menu option 2
			elif op2 == "2":
				try:
					pub_file =  str(input("Введите имя файла с открытым ключом\n> "))
					public_key = []
					with open(pub_file,"r") as pub:
						for line in pub:
							if int(line[:-1]) <= 0:
								raise Exception()
							public_key.append(int(line[:-1]))
				except:
					print ("\nНеверный ключ!\n")
					continue
				break_cipher(ct,public_key)
			else:
				print ("\nНедопустимый параметр!\n")
				continue


		# Main menu option 3
		elif op == "3":
			try:
				size = int(input("Введите размер ключа (в байтах):\n> "))
				key = gen_keypair(size*8)
				print ("\nПара ключей, сгенерированная для шифрования вашего открытого текста:\n\nОткрытый ключ > " + str(key[0]) + "\n\nPrivate Key(w,q,r) > " + str(key[1]))
				with open("publickey.txt","w") as pub:
					for n in key[0]:
						pub.write(str(n) + "\n")
				with open("privatekey.txt","w") as prv:
					prv.write("w:\n")
					for n in key[1][0]:
						prv.write(str(n) + "\n")
					prv.write("q:\n")
					prv.write(str(key[1][1]) + "\n")
					prv.write("r:\n")
					prv.write(str(key[1][2]) + "\n")
				print ("\nОткрытый и закрытый ключи были сохранены в 'publickey.txt' и 'privatekey.txt' соответственно.\n")
			except:
				print ("\nОшибка ввода\n")
				continue


		# Main menu option 4
		elif op == "4":
			print("Для понимания того, как мы можем взломать криптосистему Меркля-Хеллмана с рюкзачным шифром, сначала нам нужно понять, что такое решётки (обратите внимание, что для понимания потребуется некоторое элементарное знание линейной алгебры). \nМы можем определить решётку L как ℤ-линейную оболочку набора из n линейно независимых векторов. Или, проще говоря:\n\nL = {a1v1+a2v2+...+anvn, где ai ∈ ℤ}\nВекторы v1,...,vn образуют базис L.\nТеперь давайте проанализируем, как мы можем связать это с взломом рюкзачного шифра Меркля-Хеллмана.\n\nПредположим, у вас есть матрица X размером 1xN и матрица Y размером 1x1, и вы хотите найти матрицу решения S размером Nx1 для матричного уравнения: XS = Y, где элементы S могут быть только 0 или 1 (в контексте рюкзачного шифра Меркля-Хеллмана, S было бы открытым текстом, который атакующий пытается определить).\n\nОбратите внимание, что если S - это решение матричного уравнения XS = Y, то матричное уравнение MK = C также будет верным.\n\nТеперь рассмотрим m1, m2, ..., mn как столбцы M. Мы можем записать C как C = K1,1m1 + K2,1m2 + ... + Kn,1mn. Это означает, что C фактически является решёткой, охваченной столбцами M.\n\nТеперь еще раз обратим внимание, что поскольку элементы C могут быть только 0 или 1, евклидова длина вектора C будет довольно короткой:\n\n‖ C ‖ = sqrt(S12,S22...Sn2) <= sqrt(n)\n\nИ если бы мы рассчитали C, то мы бы также знали S, другими словами, мы бы знали бинарную форму открытого текста.\n\nВот где на сцену выходит алгоритм LLL (созданный Арьеном Ленстрой, Гендриком Ленстрой и Ласло Ловасом). При наличии базиса для решётки на входе этот алгоритм вычисляет уменьшенный базис (базис с короткими и близкими к ортогональным векторам) той же решётки.\n\nЕсли мы используем матрицу M в качестве входных данных, алгоритм LLL выдаст короткие векторы в решётке, охваченной столбцами M, что означает (хотя это не гарантировано), что существует достаточно хороший шанс найти C среди этих векторов.")
		elif op == "5":
			return 0
		else:
			print ("\nНедопустимый параметр!\n")

if __name__ == "__main__":
	main()
