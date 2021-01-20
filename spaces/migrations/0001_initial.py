# Generated by Django 3.1.5 on 2021-01-20 05:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='BreakDay',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.CharField(max_length=10)),
            ],
            options={
                'db_table': 'breakdays',
            },
        ),
        migrations.CreateModel(
            name='DetailSpace',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=18)),
                ('information', models.CharField(max_length=500)),
                ('image', models.URLField(max_length=2000)),
                ('min_reservation_time', models.IntegerField()),
                ('min_people', models.IntegerField()),
                ('max_people', models.IntegerField()),
                ('price', models.IntegerField()),
            ],
            options={
                'db_table': 'detail_spaces',
            },
        ),
        migrations.CreateModel(
            name='Facility',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'facilities',
            },
        ),
        migrations.CreateModel(
            name='Space',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=18)),
                ('simple_information', models.CharField(max_length=27)),
                ('main_information', models.CharField(max_length=500)),
                ('main_image', models.URLField(max_length=2000)),
                ('site_url', models.URLField(max_length=2000, null=True)),
                ('email', models.EmailField(max_length=245)),
                ('phone_number', models.CharField(max_length=11)),
                ('main_phone_number', models.CharField(max_length=20)),
                ('open_time', models.CharField(max_length=10)),
                ('close_time', models.CharField(max_length=10)),
                ('latitude', models.DecimalField(decimal_places=6, max_digits=10, null=True)),
                ('longitude', models.DecimalField(decimal_places=6, max_digits=10, null=True)),
                ('location', models.CharField(max_length=20, null=True)),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.host')),
            ],
            options={
                'db_table': 'spaces',
            },
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=20)),
            ],
            options={
                'db_table': 'tags',
            },
        ),
        migrations.CreateModel(
            name='Type',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=15)),
            ],
            options={
                'db_table': 'types',
            },
        ),
        migrations.CreateModel(
            name='TimePrice',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('time_reservation_type', models.CharField(max_length=20)),
                ('excess_price', models.IntegerField(null=True)),
                ('price', models.IntegerField()),
                ('detail_space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.detailspace')),
            ],
            options={
                'db_table': 'time_prices',
            },
        ),
        migrations.CreateModel(
            name='SubImage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image_url', models.URLField(max_length=2000)),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
            ],
            options={
                'db_table': 'sub_images',
            },
        ),
        migrations.CreateModel(
            name='SpaceTag',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.tag')),
            ],
            options={
                'db_table': 'space_tags',
            },
        ),
        migrations.CreateModel(
            name='SpaceFacility',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('facility', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.facility')),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
            ],
            options={
                'db_table': 'space_facilities',
            },
        ),
        migrations.CreateModel(
            name='SpaceBreakday',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('breakday', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.breakday')),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
            ],
            options={
                'db_table': 'space_breakdays',
            },
        ),
        migrations.AddField(
            model_name='space',
            name='types',
            field=models.ManyToManyField(db_table='space_types', to='spaces.Type'),
        ),
        migrations.CreateModel(
            name='ReservationNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=100)),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
            ],
            options={
                'db_table': 'reservation_notes',
            },
        ),
        migrations.CreateModel(
            name='PackagePrice',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=18)),
                ('start_time', models.DateTimeField()),
                ('end_time', models.DateTimeField()),
                ('price', models.IntegerField()),
                ('people', models.IntegerField()),
                ('excess_price', models.IntegerField()),
                ('detail_space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.detailspace')),
            ],
            options={
                'db_table': 'package_prices',
            name='Like',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_liked', models.BooleanField(default=False)),
                ('space', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.user')),
            ],
            options={
                'db_table': 'likes',
            },
        ),
        migrations.CreateModel(
            name='DetailType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=45)),
                ('detail_space', models.ManyToManyField(db_table='detail_space_types', to='spaces.DetailSpace')),
            ],
            options={
                'db_table': 'detail_types',
            },
        ),
        migrations.AddField(
            model_name='detailspace',
            name='space',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='spaces.space'),
        ),
        migrations.CreateModel(
            name='DetailFacility',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=45)),
<<<<<<< HEAD
                ('facility_type', models.CharField(max_length=45)),
=======
                ('english_name', models.CharField(max_length=45)),
>>>>>>> 95a045f0a187ab0bb397a18ca65361ac03633838
                ('detail_space', models.ManyToManyField(db_table='detail_space_facilities', to='spaces.DetailSpace')),
            ],
            options={
                'db_table': 'detail_facilities',
            },
        ),
    ]
