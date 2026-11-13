# Homebrew formula template. Copy to Formula/agentharden.rb in a tap repo named `homebrew-tap`
# and update `url` and `sha256` after each GitHub release. It installs from the GitHub tag, so it needs no PyPI.
class Agentharden < Formula
  include Language::Python::Virtualenv

  desc "Offline security scanner that turns findings into an AI-ready fix prompt"
  homepage "https://github.com/saideepreddy7781/agentharden"
  url "https://github.com/saideepreddy7781/agentharden/archive/refs/tags/v0.2.1.tar.gz"
  sha256 "661a7e120b7437a853312218cdfa79c13b6edb40dcdb03e1d3f6041aa2f031a1"
  license "Apache-2.0"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agentharden --version")
  end
end
