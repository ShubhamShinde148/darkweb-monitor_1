def generate_qr_code(data):
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    return img

def format_date(date):
    return date.strftime("%Y-%m-%d %H:%M:%S")

def generate_unique_id():
    import uuid
    return str(uuid.uuid4())