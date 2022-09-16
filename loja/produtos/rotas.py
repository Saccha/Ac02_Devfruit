import os
from flask import redirect, render_template, url_for, flash, request, abort, session, current_app
from .forms import Addprodutos
from loja import db, app, basedir
from .models import Marca, Categoria, Produto
from werkzeug.utils import secure_filename
import secrets, os
from datetime import datetime
  

def marcas():
    marcas = marcas = Marca.query.join(Produto, (Marca.id == Produto.marca_id)).all()
    return marcas

def categorias():
    categorias = Categoria.query.join(Produto, (Categoria.id == Produto.categoria_id)).all()
    return categorias

@app.route('/')
def home():
    pagina = request.args.get('pagina',1,type=int)
    produtos = Produto.query.filter(Produto.stock > 0).order_by(Produto.id.desc()).paginate(page=pagina,per_page=9)   
    return render_template('produtos/index.html', produtos=produtos, marcas=marcas(), categorias=categorias())


@app.route('/search',methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        form = request.form
        search_value= form['search_string']
        search="%{0}%".format(search_value)
        produtos = Produto.query.filter(Produto.name.like(search)).all()
        return render_template('produtos/pesquisar.html', produtos=produtos, marcas=marcas(), categorias=categorias())
    else:
        return redirect('/')


@app.route('/marca/<int:id>')
def get_marca(id):
    get_m = Marca.query.filter_by(id=id).first_or_404()
    pagina = request.args.get('pagina',1,type=int)

  
    marca = Produto.query.filter_by(marca=get_m).paginate(page=pagina,per_page=9)

    return render_template('produtos/index.html',marca=marca, marcas=marcas(), categorias=categorias(), get_m=get_m)




@app.route('/produto/<int:id>')
def pagina_unica(id):
    produto = Produto.query.get_or_404(id)
    return render_template('produtos/pagina_unica.html',produto=produto, marcas=marcas(), categorias=categorias())






@app.route('/categoria/<int:id>')
def get_categoria(id):
    pagina = request.args.get('pagina',1,type=int)
    get_cat = Categoria.query.filter_by(id=id).first_or_404()
    get_cat_prod = Produto.query.filter_by(categoria= get_cat).paginate(page=pagina,per_page=9)

    return render_template('produtos/index.html', get_cat_prod=get_cat_prod, categorias=categorias(), marcas=marcas(), get_cat=get_cat)


@app.route('/addmarca', methods=['GET', 'POST'])
def addmarca():
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))
    if request.method == "POST":
        getmarca = request.form.get('marca')
        marca = Marca(name=getmarca)
        db.session.add(marca)
        flash(f'A marca {getmarca} foi cadastrada com sucesso', 'success')
        db.session.commit()
        return redirect(url_for('addmarca'))
    return render_template('/produtos/addmarca.html',marcas='marcas')

@app.route('/updatemarca/<int:id>', methods=['GET', 'POST'])
def updatemarca(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))
    updatemarca=Marca.query.get_or_404(id)
    marca = request.form.get('marca')
    if request.method == 'POST':
        updatemarca.name= marca
        flash(f'A marca foi atualizada com sucesso', 'success')
        db.session.commit()
        return redirect(url_for('marcas'))

    return render_template('/produtos/updatemarca.html',title='Atualizar Marca', updatemarca=updatemarca)

@app.route('/deletemarca/<int:id>', methods=['POST'])
def deletemarca(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))

    marca=Marca.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(marca)
        db.session.commit()
        flash(f'A marca {marca.name} foi deletada com sucesso', 'success')
        return redirect(url_for('admin'))
    flash(f'A marca {marca.name} não foi deletada', 'warning')
    return redirect(url_for('admin'))

@app.route('/updatecat/<int:id>', methods=['GET', 'POST'])
def updatecat(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))
    updatecat=Categoria.query.get_or_404(id)
    categoria = request.form.get('categoria')
    if request.method == 'POST':
        updatecat.name= categoria
        flash(f'A categoria foi atualizada com sucesso', 'success')
        db.session.commit()
        return redirect(url_for('categorias'))

    return render_template('/produtos/updatemarca.html',title='Atualizar Categoria', updatecat=updatecat)

@app.route('/deletecategoria/<int:id>', methods=['POST'])
def deletecategoria(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))

    categoria=Categoria.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(categoria)
        db.session.commit()
        flash(f'A categoria {categoria.name} foi deletada com sucesso', 'success')
        return redirect(url_for('admin'))
    flash(f'A categoria {categoria.name} não foi deletada','warning')
    return redirect(url_for('admin'))

@app.route('/addcat', methods=['GET', 'POST'])
def addcat():
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))

    if request.method == "POST":
        getmarca = request.form.get('categoria')
        cat = Categoria(name=getmarca)
        db.session.add(cat)
        flash(f'A Categoria {getmarca} foi cadastrada com sucesso', 'success')
        db.session.commit()
        return redirect(url_for('addcat'))
    return render_template('/produtos/addmarca.html',categoria='categoria')

@app.route('/addproduto', methods=['GET', 'POST'])
def addproduto():
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))

    marcas = Marca.query.all()
    categorias = Categoria.query.all()
    form = Addprodutos(request.form)
    if request.method == 'POST':

        name= form.name.data
        price = form.price.data
        discount = form.discount.data
        stock = form.stock.data
        weight= form.weight.data
        description= form.description.data
        marca= request.form.get('marca')
        categoria= request.form.get('categoria')

        #image=photos.save(request.files.get('image'), name=secrets.token_hex(10) + ".")

        addpro = Produto(name=name,price=price,discount=discount,stock=stock,weight=weight,description=description,marca_id=marca,categoria_id=categoria)
        db.session.add(addpro) 
        flash(f'O produto {name} foi adicionado com sucesso')
        db.session.commit()
        return redirect(url_for('admin'))
    
    return render_template('/produtos/addproduto.html',title='Cadastrar Produtos', form=form, marcas=marcas, categorias=categorias)

@app.route('/updateproduto/<int:id>', methods=['GET', 'POST'])
def updateproduto(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))
    
    marcas = Marca.query.all()
    categorias = Categoria.query.all()
    produto = Produto.query.get_or_404(id)
    marca= request.form.get('marca')
    categoria= request.form.get('categoria')
    form= Addprodutos(request.form)
    if request.method == 'POST':

        produto.name = form.name.data
        produto.price = form.price.data
        produto.description = form.description.data
        produto.stock = form.stock.data
        produto.weight = form.weight.data
        produto.discount = form.discount.data

        produto.marca_id = marca
        produto.categoria_id = categoria

        # if request.files.get('image'):
        # try:
        #     os.unlink(os.path.join(current_app.root_path,"static/images/"+produto.image))
        #     produto.image=photos.save(request.files.get('image'), name=secrets.token_hex(10) + ".")
        # except:
        #     produto.image=photos.save(request.files.get('image'), name=secrets.token_hex(10) + ".")

        

        db.session.commit()
        flash(f'O produto foi atualizado com sucesso','success')
        return redirect(url_for('admin'))

    form.name.data = produto.name
    form.price.data = produto.price
    form.description.data = produto.description
    form.stock.data = produto.stock
    form.weight.data = produto.weight
    form.discount.data = produto.discount


    return render_template('/produtos/updateproduto.html',title='Atualizar Produtos', form=form, marcas=marcas, categorias=categorias, produto=produto)


@app.route('/deleteproduto/<int:id>', methods=['POST'])
def deleteproduto(id):
    if 'email' not in session:
        flash(f'Realize o login!','danger')
        return redirect(url_for('login'))

    produto=Produto.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(produto)
        db.session.commit()
        flash(f'O produto {produto.name} foi deletada com sucesso', 'success')
        return redirect(url_for('admin'))
    flash(f'O produto {produto.name} não foi deletada','warning')
    return redirect(url_for('admin'))
