IMAGE_NAME = aws-third-party-access
CTN_NAME = aws-third-party-access

.PHONY: build run

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run -it --rm \
		--name $(CTN_NAME) \
		-v $(PWD):/home/appuser/aws-third-party-access \
		-v $(HOME)/.aws:/home/appuser/.aws \
		$(IMAGE_NAME)

cleanup:
	-docker stop $(CTN_NAME)
	-docker rm $(CTN_NAME)
	-docker rmi $(IMAGE_NAME)
