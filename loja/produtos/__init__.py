





























'''
UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER'] = os.path.join(basedir,'static/images')

    if request.method=="POST":
        file = request.files['image']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('addproduto'))
        
        filename = secure_filename(file.filename)
        file.save(app.config['UPLOAD_FOLDER'], filename)
        ''' 