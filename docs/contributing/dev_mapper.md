# Add a new mapper

## Mapper Development
First develop your mapper. We are using `numbat` to manipulate the db used by sourcetrail to store the pieces of information to show in Sourcetrail. Everything is explained in Numbat's Getting Started Tutorial. (Numbat will be open-sourced before the end of March 2024)

Then, add the required dependencies into `pyproject.toml`.

## Integration into the main program
Once the mapper is ready, it should be integrated into `pyrrha` CLI by adding the corresponding subcommand in the `src/pyrrha_mapper/__main__.py`. The CLI system is handled with [click](https://click.palletsprojects.com)

The subcommand corresponds to a function implementing the main of your mapper and some decorators to declare the subcommand name, its options and its arguments. 

The command name is declared with the following decorator. It automatically adds two options: `--db` to indicate the path of the db and `-d` to set the log level at `DEBUG` instead of `INFO`.

```python linenums="121"
@pyrrha.command(
    'my_mapper',  # the command name
    cls=MapperCommand,  # it will add default options
    short_help='A quick help.',
    help='A longer help, display only for this command help, no the general one.'
)
```
You can now add options and arguments if needed. Below you can found some examples but as `click` is a powerful tool, check the documentation about [`click.option`](https://click.palletsprojects.com/options/) and [`click.argument`](https://click.palletsprojects.com/arguments/) for more details.
```python linenums="127"
# a flag option (if activated = True, else False)
@click.option('-o', '--myoption', # short and long option name
              help='An help message',
              is_flag=True,
              default=False,
              show_default=False)
# an option to precise the number of threads
@click.option('-j', '--jobs',
              help='Number of parallel jobs created (threads).',
              type=click.IntRange(1, multiprocessing.cpu_count(), clamp=True),
              metavar='INT',
              default=1,
              show_default=True)
# an argument
@click.argument('target_directory',
                type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
```
Then, you can implement the function that will run your mapper. It will have as parameters all
the options and arguments declared before. We also provide two utilities function which sets up the logs and create/open a db given a path.

!!! note 
    
    Do not forget that by default, the first two parameters will be `debug: bool, db: Path`.

```python linenums="143"
def my_mapper(debug: bool, db: Path, myoption, jobs, target_directory):
    setup_logs(debug)
    db_instance = setup_db(db)
    
    # main work 
    
    db_instance.close() # do not forget to close your db connection    
```

???+ abstract "Final ` __main__.py`"
    ``` py linenums="121" 
    @pyrrha.command(
        'my_mapper',  # the command name
        cls=MapperCommand,  # it will add default options
        short_help='A quick help.',
        help='A longer help, display only for this command help, no the general one.'
    )
    # a flag option (if activated = True, else False)
    @click.option('-o', '--myoption', # short and long option name
                  help='An help message',
                  is_flag=True,
                  default=False,
                  show_default=False)
    # an option to precise the number of threads
    @click.option('-j', '--jobs',
                  help='Number of parallel jobs created (threads).',
                  type=click.IntRange(1, multiprocessing.cpu_count(), clamp=True),
                  metavar='INT',
                  default=1,
                  show_default=True)
    # an argument
    @click.argument('target_directory',
                    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
    def my_mapper(debug: bool, db: Path, myoption, jobs, target_directory):
        setup_logs(debug)
        db_instance = setup_db(db)
        
        # main work 
        
        db_instance.close() # do not forget to close your db connection  
    
    if __name__ == '__main__':
        pyrrha()

    ```


## Documentation
Finally, you should add a page relative to your mapper inside the documentation. The list below resume the steps to add your mapper in every required places of the documentation:

1. Write your documentation in a markdown file that should be place into the `docs/mappers` folder.

    !!! tip
        We are using `material` theme of the `mkdocs` doc system. It provides a lot of nice features to improve your documentation like this note block. Do not hesitate to take a look at their [documentation](https://squidfunk.github.io/mkdocs-material/reference/)!

2. Add your mapper in mapper lists (in `README.md` and in `docs/mappers/mappers.md`).
3. Complete the `nav` section in the `mkdocs.yml` file to add your file in the site navigation system.

    ```yaml linenums="33" hl_lines="7"
    nav:
      - Home: index.md
      - Installation: installation.md
      - Mappers:
          - mappers/mappers.md
          - Filesystem: mappers/fs.md
          - My Mapper: mappers/my_mapper.md
    ```