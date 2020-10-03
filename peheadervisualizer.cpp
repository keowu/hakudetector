#include "peheadervisualizer.h"
#include "ui_peheadervisualizer.h"

peheadervisualizer::peheadervisualizer(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::peheadervisualizer)
{
    ui->setupUi(this);
}

peheadervisualizer::~peheadervisualizer()
{
    delete ui;
}

void peheadervisualizer::on_pushButton_clicked()
{


}
