import os
from flask import redirect, render_template, url_for, flash, request, abort, session, current_app, make_response
from .forms import ClienteForm, ClienteLoginForm
from flask_bcrypt import Bcrypt
from loja import db, app, basedir, bcrypt, login_manager
from loja.produtos.models import Produto, Marca, Categoria
from werkzeug.utils import secure_filename
import secrets, os
from datetime import datetime
from .models import Cliente, ClientePedido
from flask_login import login_required, current_user, login_user, logout_user
import pdfkit 
  
@app.route('/cliente/cadastrar',methods=['GET', 'POST'])
def cadastrar_cliente():
    form= ClienteForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        cadastrar = Cliente(name=form.name.data,cpf=form.cpf.data,contact=form.contact.data, email=form.email.data, password=hash_password,state=form.state.data,city=form.city.data,address=form.address.data,cep=form.cep.data)
        db.session.add(cadastrar)
        db.session.commit()
        flash(f'Obrigado por se cadastrar,{form.name.data}! ','success')
        return redirect(url_for('login'))
    return render_template('cliente/cadastro.html',form=form)

@app.route('/cliente/login',methods=['GET', 'POST'])
def clienteLogin():
    form= ClienteLoginForm()
    if request.method == 'POST':
        user = Cliente.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Você já está logado, {user.name}!','success')
            next = request.args.get('next')
            return redirect(next or url_for('home'))
        flash(f'Senha e/ou e-mail incorretos, tente novamente.','danger')
        return redirect(url_for('clienteLogin'))
    return render_template('cliente/login.html', form=form)

@app.route('/cliente/logout')
def clienteLogout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/pedido')
@login_required
def pedido():
    if current_user.is_authenticated:
        cliente_id = current_user.id
        notafiscal = secrets.token_hex(5)
        try:
            p_order=ClientePedido(notafiscal=notafiscal, cliente_id=cliente_id, pedido=session['LojainCarrinho'])  
            db.session.add(p_order)
            db.session.commit()
            session.pop('LojainCarrinho')
            flash('Seu pedido foi salvo com sucesso', 'success')
            return redirect(url_for('pedidos',notafiscal=notafiscal)) 
        except Exception as e:
            print(e)
            flash('Não foi possível processar seu pedido', 'danger')
            return redirect(url_for('getCart'))


@app.route('/pedidos/<notafiscal>')
@login_required
def pedidos(notafiscal):
    if current_user.is_authenticated:
        gTotal = 0
        subTotal = 0
        cliente_id = current_user.id
        cliente = Cliente.query.filter_by(id=cliente_id).first()
        pedidos = ClientePedido.query.filter_by(cliente_id=cliente_id, notafiscal=notafiscal).order_by(ClientePedido.id.desc()).first()

        for _key, produto in pedidos.pedido.items():
            desconto = (produto['discount']/100) * float(produto['price'])
            subTotal += float(produto['price'])*int(produto['quantity'])
            subTotal -= desconto
            imposto = ("%.2f" % (.06 * float(subTotal)))
            gTotal =  ("%.2f" % (1.06 * float(subTotal)))
    else:
        return redirect(url_for('clienteLogin'))
    return render_template('cliente/pedido.html', notafiscal=notafiscal, imposto=imposto, subTotal=subTotal, gTotal=gTotal, cliente=cliente, pedidos=pedidos)


@app.route('/get_pdf/<notafiscal>', methods=['POST'])
@login_required
def get_pdf(notafiscal):
    if current_user.is_authenticated:
        gTotal = 0
        subTotal = 0
        cliente_id = current_user.id
        if request.method == 'POST':

            cliente = Cliente.query.filter_by(id=cliente_id).first()
            pedidos = ClientePedido.query.filter_by(cliente_id=cliente_id, notafiscal=notafiscal).order_by(ClientePedido.id.desc()).first()

            for _key, produto in pedidos.pedido.items():
                desconto = (produto['discount']/100) * float(produto['price'])
                subTotal += float(produto['price'])*int(produto['quantity'])
                subTotal -= desconto
                imposto = ("%.2f" % (.06 * float(subTotal)))
                gTotal =  ("%.2f" % (1.06 * float(subTotal)))
            

    
            rendered=render_template('cliente/pdf.html', notafiscal=notafiscal, imposto=imposto, subTotal=subTotal, gTotal=gTotal, cliente=cliente, pedidos=pedidos)
            
            
            pdf = pdfkit.from_string(rendered, False)
            response = make_response(pdf)
            response.headers['content-Type']='application/pdf'
            response.headers['content-Disposition']='inline:filename='+ notafiscal+'. pdf'
            return response
            
    return redirect(url_for('pedidos'))






    


