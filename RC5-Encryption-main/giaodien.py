from tkinter import *
import tkinter as tk

top=tk.Tk()
top.geometry("600x550")
top.resizable(0,0)
top.title("File MÃ HÓA AES")
title="MÃ HÓA USING AES"
msgtitle=Message(top,text=title)
msgtitle.config(font=('helvetica',17,'bold'),width=300)
msgtitle.pack()

sp="---------------------------------------------------------------------"
sp_title=Message(top,text=sp)
sp_title.config(font=('arial',12),width=650)
sp_title.pack()

passlabel = Label(top, text="NHẬP MÃ KHÓA AES :")
passlabel.pack()

passg = Entry(top, width=60)
passg.config(highlightthickness=1,highlightbackground="blue")
passg.pack()

textlableEn = Label(top, text="BẢN RÕ")
textlableEn.pack()

textgEn = Text(top, width= 50,height=1)
textgEn.config(highlightthickness=1,)
textgEn.pack()

textlableDe = Label(top, text="BẢN MÃ HÓA")
textlableDe.pack()

textgDe = Text(top, width= 50 ,height=1 )
textgDe.config(highlightthickness=1,)
textgDe.pack()

txt = Label(top, text="KHÓA ĐƯỢC SINH RA :")
txt.pack()
getkey = StringVar()
textlableKey = Label(top, text="KEY",textvariable=getkey)
textlableKey.pack()

get_encrypt_string=Button(top,text="MÃ HÓA CHUỖI",width=28,height=3,command=get_encrypt_string)

get_decrypt_string=Button(top,text="GIẢI MÃ CHUỖI",width=28,height=3,command=get_decrypt_string)

get_decrypt_string.pack(side=BOTTOM)
get_encrypt_string.pack(side=BOTTOM)

encrypt=Button(top,text="MÃ HÓA File",width=28,height=3,command=encrypt)
encrypt.pack(side=LEFT)
decrypt=Button(top,text="GIẢI MÃ File",width=28,height=3,command=decrypt)
decrypt.pack(side=RIGHT)

top.mainloop()