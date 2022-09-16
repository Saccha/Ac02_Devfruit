from flask import redirect, render_template, url_for, flash, request, abort, session, current_app
from loja import db, app
from loja.produtos.models import Produto
from loja.produtos.rotas import marcas,categorias
import json


def M_Dicionarios(dic1,dic2):
    if isinstance(dic1,list) and isinstance(dic2,list):
        return dic1 + dic2
    elif isinstance(dic1,dict) and isinstance(dic2,dict):
        return dict(list(dic1.items()) + list(dic2.items()))
    return False




@app.route('/addCart', methods=['POST'])
def AddCart():
    try:
        produto_id = request.form.get('produto_id')
        quantity = request.form.get('quantity')
        weight = request.form.get('weight')
        i=1
        produto = Produto.query.filter_by(id=produto_id).first()

        if produto_id and quantity and request.method == "POST":
            DicItems = {produto_id: {'name':produto.name,'price':produto.price, 'discount':produto.discount, 'quantity':quantity, 'weight':produto.weight }}
            if 'LojainCarrinho' in session:
                
                if produto_id in session['LojainCarrinho']:
                    for key, item in session['LojainCarrinho'].items():
                        if int(key) == int(produto_id):
                            session.modified= True
                            i+=int(item['quantity'])
                            item['quantity']=str(i)

                else:
                    session['LojainCarrinho'] = M_Dicionarios(session['LojainCarrinho'],DicItems)
                    return redirect(request.referrer)
            else:
                session['LojainCarrinho'] = DicItems
                return redirect(request.referrer)

    except Exception as e:
        print(e)
    finally:
        return redirect(request.referrer)


@app.route('/carrinho')
def getCart():
    if 'LojainCarrinho' not in session or len(session['LojainCarrinho'])<=0:
        print(session['LojainCarrinho'])
        return redirect(url_for('home'))
    subtotal = 0
    valorpagar = 0
    for key, produto in session['LojainCarrinho'].items():
        discount = (produto['discount']/100)*float(produto['price'])
        subtotal += float(produto['price'])*int(produto['quantity'])
        subtotal -= discount
        imposto = ("%.2f"%(.06 * float(subtotal)))
        valorpagar = float("%.2f" %(1.06 * subtotal))
            
    return render_template('produtos/carrinho.html', imposto=imposto, valorpagar=valorpagar, marcas= marcas(),categorias=categorias())

@app.route('/updateCarrinho/<int:code>',methods=['POST'])
def updateCarrinho(code):
    if 'LojainCarrinho' not in session or len(session['LojainCarrinho'])<=0:
        return redirect(url_for('home'))
    if request.method == 'POST':
        quantity = int(request.form.get('quantity'))
        try:
            session.modified = True
            for key, item in session['LojainCarrinho'].items():
                if int(key) == code:
                    item['quantity']=quantity
                    flash('Carrinho atualizado com sucesso','success')
                    return redirect(url_for('getCart'))
                    
        except Exception as e:
            print(e)
            return redirect(url_for('getCart'))



@app.route('/deleteItem/<int:id>')
def deleteItem(id):
    if 'LojainCarrinho' not in session or len(session['LojainCarrinho'])<=0:
        return redirect(url_for('home'))

    try:
        session.modified = True
        for key, item in session['LojainCarrinho'].items():
            if int(key) == id:
                session['LojainCarrinho'].pop(key,None)
                flash('Item removido com sucesso','success')
                return redirect(url_for('getCart'))
                
    except Exception as e:
        print(e)
        return redirect(url_for('getCart'))

@app.route('/limparCarrinho')
def limparCarrinho():
    try:
        session.pop('LojainCarrinho',None)
        return redirect(url_for('home'))
                
    except Exception as e:
        print(e)
        



@app.route('/vazio')
def vazio_Cart():
    try:
        session.clear()
        return redirect(url_for('home'))

    except Exception as e:
        print (e)
    