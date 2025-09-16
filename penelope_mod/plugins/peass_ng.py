from .base import Module
from argparse import ArgumentParser
import shlex
from penelope_mod.constants import URLS
from penelope_mod.ui import paint
from penelope_mod.context import ctx
from penelope_mod.io import ask, stdout

class peass_ng(Module):
    category = "Privilege Escalation"
    def run(session, args):
        """
        Run the latest version of PEASS-ng in the background
        """
        if session.OS == 'Unix':
            parser = ArgumentParser(prog='peass_ng', description="peass-ng module", add_help=False)
            parser.add_argument("-a", "--ai", help="Analyze linpeas results with chatGPT", action="store_true")
            try:
                arguments = parser.parse_args(shlex.split(args))
            except SystemExit:
                return
            if arguments.ai:
                try:
                    from openai import OpenAI
                except Exception as e:
                    ctx.logger.error(e)
                    return False

            output_file = session.script(URLS['linpeas'])

            if arguments.ai:
                api_key = input("Please enter your chatGPT API key: ")
                assert len(api_key) > 10

                with open(output_file, "r") as file:
                    content = file.read()

                client = OpenAI(api_key=api_key)
                stream = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                    {"role": "system", "content": "You are a helpful assistant helping me to perform penetration test to protect the systems"},
                    {
                        "role": "user",
                        "content": f"I am pasting here the results of linpeas. Based on the output, I want you to tell me all possible ways the further exploit this system. I want you to be very specific on your analysis and not write generalities and uneccesary information. I want to focus only on your specific suggestions.\n\n\n {content}"
                    }
                    ],
                stream=True
                )

                print('\n═════════════════ chatGPT analysis START ════════════════')
                for chunk in stream:
                    if chunk.choices[0].delta.content:
                        stdout(chunk.choices[0].delta.content.encode())
                print('\n═════════════════ chatGPT analysis END ════════════════')

        elif session.OS == 'Windows':
            ctx.logger.error("This module runs only on Unix shells")
            while True:
                answer = ask(f"Use {paint('upload_privesc_scripts').GREY_white}{paint(' instead? (Y/n): ').yellow}").lower()
                if answer in ('y', ''):
                    # Avoiding circular import; call via menu
                    ctx.menu.do_run('upload_privesc_scripts')
                    break
                elif answer == 'n':
                    break

